/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package v1

import (
	"context"
	"errors"
	"github.com/nuts-foundation/go-did/did"
	httpTest "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var payload = []byte("Hello, World!")

func TestApiWrapper_GetTransaction(t *testing.T) {
	transaction := dag.CreateTestTransactionWithJWK(1)

	t.Run("ok", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().GetTransaction(hash.EqHash(transaction.Ref())).Return(transaction, nil)

		resp, err := wrapper.GetTransaction(nil, GetTransactionRequestObject{Ref: transaction.Ref().String()})

		require.NoError(t, err)
		assert.Equal(t, string(transaction.Data()), httpTest.GetResponseBody(t, resp.VisitGetTransactionResponse))
	})
	t.Run("error", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().GetTransaction(gomock.Any()).Return(nil, errors.New("failed"))

		resp, err := wrapper.GetTransaction(nil, GetTransactionRequestObject{Ref: transaction.Ref().String()})

		assert.EqualError(t, err, "failed")
		assert.Nil(t, resp)
	})
	t.Run("invalid hash", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}

		resp, err := wrapper.GetTransaction(nil, GetTransactionRequestObject{Ref: "1234"})

		assert.EqualError(t, err, "invalid hash: incorrect hash length (2)")
		assert.Nil(t, resp)
	})
	t.Run("not found", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().GetTransaction(gomock.Any()).Return(nil, dag.ErrTransactionNotFound)

		resp, err := wrapper.GetTransaction(nil, GetTransactionRequestObject{Ref: transaction.Ref().String()})

		assert.EqualError(t, err, "transaction not found")
		assert.Nil(t, resp)
	})
}

func TestApiWrapper_GetPeerDiagnostics(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	var networkClient = network.NewMockTransactions(mockCtrl)
	wrapper := &Wrapper{Service: networkClient}
	networkClient.EXPECT().PeerDiagnostics().Return(map[transport.PeerID]transport.Diagnostics{"foo": {
		Uptime:               1000 * time.Second,
		Peers:                []transport.PeerID{"bar"},
		NumberOfTransactions: 5,
		SoftwareVersion:      "1.0",
		SoftwareID:           "Test",
	}})
	expected := map[string]PeerDiagnostics{
		"foo": {
			Uptime:               1000 * time.Second,
			Peers:                []transport.PeerID{"bar"},
			NumberOfTransactions: 5,
			SoftwareVersion:      "1.0",
			SoftwareID:           "Test",
		},
	}

	resp, err := wrapper.GetPeerDiagnostics(nil, GetPeerDiagnosticsRequestObject{})

	require.NoError(t, err)
	assert.Equal(t, resp.(GetPeerDiagnostics200JSONResponse), GetPeerDiagnostics200JSONResponse(expected))
}

func TestApiWrapper_RenderGraph(t *testing.T) {
	t.Run("ok - no query params", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().ListTransactionsInRange(uint32(0), uint32(dag.MaxLamportClock))

		resp, err := wrapper.RenderGraph(nil, RenderGraphRequestObject{})

		require.NoError(t, err)
		assert.NotEmpty(t, httpTest.GetResponseBody(t, resp.VisitRenderGraphResponse))
	})
	t.Run("ok - with query params", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().ListTransactionsInRange(uint32(1), uint32(4))
		start := 1
		end := 4

		resp, err := wrapper.RenderGraph(nil, RenderGraphRequestObject{Params: RenderGraphParams{Start: &start, End: &end}})

		require.NoError(t, err)
		assert.NotEmpty(t, httpTest.GetResponseBody(t, resp.VisitRenderGraphResponse))
	})
	t.Run("error", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		start := 5
		end := 0

		resp, err := wrapper.RenderGraph(nil, RenderGraphRequestObject{Params: RenderGraphParams{Start: &start, End: &end}})

		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid range")
		assert.Nil(t, resp)
	})
}

func TestApiWrapper_GetTransactionPayload(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	transaction := dag.CreateTestTransactionWithJWK(1)

	t.Run("ok", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().GetTransactionPayload(hash.EqHash(transaction.Ref())).Return(payload, nil)

		resp, err := wrapper.GetTransactionPayload(nil, GetTransactionPayloadRequestObject{Ref: transaction.Ref().String()})

		require.NoError(t, err)
		assert.Equal(t, string(payload), httpTest.GetResponseBody(t, resp.VisitGetTransactionPayloadResponse))
	})
	t.Run("error", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().GetTransactionPayload(gomock.Any()).Return(nil, errors.New("failed"))

		resp, err := wrapper.GetTransactionPayload(nil, GetTransactionPayloadRequestObject{Ref: transaction.Ref().String()})

		assert.Nil(t, resp)
		assert.EqualError(t, err, "failed")
	})
	t.Run("invalid hash", func(t *testing.T) {
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}

		resp, err := wrapper.GetTransactionPayload(nil, GetTransactionPayloadRequestObject{Ref: "1234"})

		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid hash: incorrect hash length (2)")
	})
}

func TestApiWrapper_ListTransactions(t *testing.T) {
	transaction := dag.CreateTestTransactionWithJWK(1)
	t.Run("200 - no query params", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().ListTransactionsInRange(uint32(0), uint32(dag.MaxLamportClock)).Return([]dag.Transaction{transaction}, nil)

		resp, err := wrapper.ListTransactions(nil, ListTransactionsRequestObject{})

		assert.NoError(t, err)
		assert.Equal(t, `["`+string(transaction.Data())+`"]`, strings.TrimSpace(httpTest.GetResponseBody(t, resp.VisitListTransactionsResponse)))
	})
	t.Run("200 - query params", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().ListTransactionsInRange(uint32(1), uint32(4)).Return([]dag.Transaction{transaction}, nil)
		start := 1
		end := 4

		resp, err := wrapper.ListTransactions(nil, ListTransactionsRequestObject{Params: ListTransactionsParams{Start: &start, End: &end}})

		assert.NoError(t, err)
		assert.NotEmpty(t, httpTest.GetResponseBody(t, resp.VisitListTransactionsResponse))
	})
	t.Run("error", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().ListTransactionsInRange(uint32(0), uint32(dag.MaxLamportClock)).Return(nil, errors.New("failed"))

		resp, err := wrapper.ListTransactions(nil, ListTransactionsRequestObject{})

		assert.Nil(t, resp)
		assert.EqualError(t, err, "failed")
	})
}

func TestWrapper_GetPeerDiagnostics(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		expected := map[transport.PeerID]transport.Diagnostics{"foo": {Uptime: 50 * time.Second}}
		networkClient.EXPECT().PeerDiagnostics().Return(expected)

		resp, err := wrapper.GetPeerDiagnostics(nil, GetPeerDiagnosticsRequestObject{})

		assert.NoError(t, err)
		actual := map[transport.PeerID]PeerDiagnostics{}
		httpTest.UnmarshalResponseBody(t, resp.VisitGetPeerDiagnosticsResponse, &actual)
		assert.Equal(t, PeerDiagnostics(expected["foo"]), actual["foo"])
	})
}

func TestWrapper_GetAddressBook(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		now := time.Now()
		next := now.Add(time.Second)
		lastError := "error"
		networkClient.EXPECT().AddressBook().Return([]transport.Contact{
			{
				Address:     "foo",
				DID:         did.MustParseDID("did:nuts:A"),
				Attempts:    1,
				LastAttempt: &now,
				NextAttempt: &next,
				Error:       &lastError,
			},
			{
				Address:  "bar",
				DID:      did.DID{},
				Attempts: 0,
			},
		})

		resp, err := wrapper.GetAddressBook(nil, GetAddressBookRequestObject{})

		assert.NoError(t, err)
		actual := resp.(GetAddressBook200JSONResponse)
		require.Len(t, actual, 2)
		// Assert first entry
		assert.Equal(t, "foo", actual[0].Address)
		assert.Equal(t, "did:nuts:A", *actual[0].Did)
		assert.Equal(t, 1, actual[0].Attempts)
		assert.Equal(t, now, *actual[0].LastAttempt)
		assert.Equal(t, next, *actual[0].NextAttempt)
		assert.Equal(t, lastError, *actual[0].Error)
		// Assert second entry
		assert.Equal(t, "bar", actual[1].Address)
		assert.Nil(t, actual[1].Did)
		assert.Equal(t, 0, actual[1].Attempts)
		assert.Nil(t, actual[1].LastAttempt)

	})
}

func TestApiWrapper_Reprocess(t *testing.T) {
	t.Run("error - missing type", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}

		resp, err := wrapper.Reprocess(nil, ReprocessRequestObject{})

		assert.Nil(t, resp)
		assert.EqualError(t, err, "missing type")
	})
	t.Run("ok", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var networkClient = network.NewMockTransactions(mockCtrl)
		wrapper := &Wrapper{Service: networkClient}
		networkClient.EXPECT().Reprocess(context.Background(), "application/did+json")

		params := ReprocessParams{Type: new(string)}
		*params.Type = "application/did+json"
		resp, err := wrapper.Reprocess(nil, ReprocessRequestObject{Params: params})

		// a go procedure is started
		time.Sleep(10 * time.Millisecond)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

func TestWrapper_ListEvents(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)
	sTime := time.Date(2022, time.December, 5, 18, 23, 45, 67, &time.Location{})
	testEvent := dag.Event{
		Error:       "error",
		Hash:        hash.EmptyHash(),
		Retries:     1,
		Latest:      &sTime,
		Transaction: tx,
		Type:        dag.TransactionEventType,
	}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetwork := network.NewMockTransactions(ctrl)
		w := &Wrapper{Service: mockNetwork}
		subscriberMock := dag.NewMockNotifier(ctrl)
		mockNetwork.EXPECT().Subscribers().Return([]dag.Notifier{subscriberMock})
		subscriberMock.EXPECT().Name().Return("test")
		subscriberMock.EXPECT().GetFailedEvents().Return([]dag.Event{testEvent}, nil)

		resp, err := w.ListEvents(nil, ListEventsRequestObject{})
		capturedEventSubscriber := resp.(ListEvents200JSONResponse)

		require.NoError(t, err)
		require.Len(t, capturedEventSubscriber, 1)
		assert.Equal(t, "test", capturedEventSubscriber[0].Name)
		require.Len(t, capturedEventSubscriber[0].Events, 1)
		capturedEvent := capturedEventSubscriber[0].Events[0]
		assert.Equal(t, testEvent.Hash.String(), capturedEvent.Hash)
		assert.Equal(t, testEvent.Type, *capturedEvent.Type)
		assert.Equal(t, tx.Ref().String(), capturedEvent.Transaction)
		assert.Equal(t, testEvent.Retries, capturedEvent.Retries)
		assert.Equal(t, "2022-12-05T18:23:45Z", *capturedEvent.LatestNotificationAttempt)
		assert.Equal(t, testEvent.Error, *capturedEvent.Error)
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetwork := network.NewMockTransactions(ctrl)
		w := &Wrapper{Service: mockNetwork}
		subscriberMock := dag.NewMockNotifier(ctrl)
		mockNetwork.EXPECT().Subscribers().Return([]dag.Notifier{subscriberMock})
		subscriberMock.EXPECT().Name().Return("test")
		subscriberMock.EXPECT().GetFailedEvents().Return(nil, errors.New("error"))

		resp, err := w.ListEvents(nil, ListEventsRequestObject{})

		assert.Nil(t, resp)
		assert.Error(t, err)
	})
}
