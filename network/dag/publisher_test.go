package dag

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReplayingPublisher(t *testing.T) {
	t.Run("empty graph at start", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)
		dag := NewBBoltDAG(db)
		payloadStore := NewBBoltPayloadStore(db)
		publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
		received := false
		document := CreateTestDocumentWithJWK(1)
		publisher.Subscribe(document.PayloadType(), func(actualDocument SubscriberDocument, actualPayload []byte) error {
			assert.Equal(t, document, actualDocument)
			received = true
			return nil
		})
		publisher.Start()

		// Now add document and write payload to trigger the observers
		dag.Add(document)
		payloadStore.WritePayload(document.PayloadHash(), []byte{1, 2, 3})

		assert.True(t, received)
	})
	t.Run("non-empty graph at start", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)
		dag := NewBBoltDAG(db)
		payloadStore := NewBBoltPayloadStore(db)
		document := CreateTestDocumentWithJWK(1)
		err := dag.Add(document)
		if !assert.NoError(t, err) {
			return
		}
		err = payloadStore.WritePayload(document.PayloadHash(), []byte{1, 2, 3})
		if !assert.NoError(t, err) {
			return
		}

		publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
		received := false
		publisher.Subscribe(document.PayloadType(), func(actualDocument SubscriberDocument, actualPayload []byte) error {
			assert.Equal(t, document, actualDocument)
			received = true
			return nil
		})
		publisher.Start()

		assert.True(t, received)
	})
}

func TestReplayingPublisher_publishDocument(t *testing.T) {
	t.Run("no subscribers", func(t *testing.T) {
		publisher, ctrl, _ := createPublisher(t)
		defer ctrl.Finish()

		publisher.publishDocument(CreateTestDocumentWithJWK(1))
	})
	t.Run("single subscriber", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()

		document := CreateTestDocumentWithJWK(1)
		store.EXPECT().ReadPayload(document.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		received := false
		publisher.Subscribe(document.PayloadType(), func(actualDocument SubscriberDocument, actualPayload []byte) error {
			assert.Equal(t, document, actualDocument)
			received = true
			return nil
		})
		publisher.publishDocument(document)
		assert.True(t, received)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()

		document := CreateTestDocumentWithJWK(1)
		store.EXPECT().ReadPayload(document.PayloadHash()).Return(nil, nil)

		received := false
		publisher.Subscribe(document.PayloadType(), func(actualDocument SubscriberDocument, actualPayload []byte) error {
			assert.Equal(t, document, actualDocument)
			received = true
			return nil
		})
		publisher.publishDocument(document)
		assert.False(t, received)

		// Now add the payload and trigger observer func
		store.EXPECT().ReadPayload(document.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		publisher.publishDocument(document)

		assert.True(t, received)
	})
	t.Run("error reading payload", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()

		document := CreateTestDocumentWithJWK(1)
		store.EXPECT().ReadPayload(document.PayloadHash()).Return(nil, errors.New("failed"))

		received := false
		publisher.Subscribe(document.PayloadType(), func(actualDocument SubscriberDocument, actualPayload []byte) error {
			received = true
			return nil
		})
		publisher.publishDocument(document)
		assert.False(t, received)
	})
	t.Run("multiple subscribers", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()

		document := CreateTestDocumentWithJWK(1)
		store.EXPECT().ReadPayload(document.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		calls := 0
		receiver := func(actualDocument SubscriberDocument, actualPayload []byte) error {
			calls++
			return nil
		}
		publisher.Subscribe(document.PayloadType(), receiver)
		publisher.Subscribe(document.PayloadType(), receiver)

		publisher.publishDocument(document)
		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers, first fails", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()

		document := CreateTestDocumentWithJWK(1)
		store.EXPECT().ReadPayload(document.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		calls := 0
		receiver := func(actualDocument SubscriberDocument, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		publisher.Subscribe(document.PayloadType(), receiver)
		publisher.Subscribe(document.PayloadType(), receiver)
		publisher.publishDocument(document)
		assert.Equal(t, 1, calls)
	})
}

func createPublisher(t *testing.T) (*replayingDAGPublisher, *gomock.Controller, *MockPayloadStore) {
	ctrl := gomock.NewController(t)
	payloadStore := NewMockPayloadStore(ctrl)
	payloadStore.EXPECT().RegisterObserver(gomock.Any())
	dag := NewMockDAG(ctrl)
	dag.EXPECT().RegisterObserver(gomock.Any())
	publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
	return publisher, ctrl, payloadStore
}
