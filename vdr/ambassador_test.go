package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

type didStoreMock struct {
	err error
}

func (d didStoreMock) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	if d.err != nil {
		return nil, nil, d.err
	}
	return &did.Document{ID: id}, &types.DocumentMetadata{}, nil
}

func (d didStoreMock) Write(document did.Document, metadata types.DocumentMetadata) error {
	panic("implement me")
}

func (d didStoreMock) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *types.DocumentMetadata) error {
	panic("implement me")
}

func Test_ambassador_resolveDIDControllers(t *testing.T) {
	n := ambassador{
		didStore: didStoreMock{},
	}
	t.Run("ok - document has no controllers, it should return the doc", func(t *testing.T) {
		id, err := did.ParseDID("did:nuts:123")
		if !assert.NoError(t, err) {
			return
		}
		nextDoc := &did.Document{ID: *id}
		got, err := n.resolveDIDControllers(nextDoc)
		assert.Len(t, got, 1)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:123", got[0].ID.String())
	})

	t.Run("ok - document has controllers, it should return the controllers", func(t *testing.T) {
		id, _ := did.ParseDID("did:nuts:123")
		ctrlID1, _ := did.ParseDID("did:nuts:abc")
		ctrlID2, _ := did.ParseDID("did:nuts:456")
		nextDoc := &did.Document{ID: *id, Controller: []did.DID{*ctrlID1, *ctrlID2}}

		got, err := n.resolveDIDControllers(nextDoc)
		assert.Len(t, got, 2)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", got[0].ID.String())
		assert.Equal(t, "did:nuts:456", got[1].ID.String())
	})

	t.Run("nok - document has unknown controllers, it should return an error", func(t *testing.T) {
		am := ambassador{
			didStore: didStoreMock{err: types.ErrNotFound},
		}
		id, _ := did.ParseDID("did:nuts:123")
		ctrlID1, _ := did.ParseDID("did:nuts:abc")
		ctrlID2, _ := did.ParseDID("did:nuts:456")
		nextDoc := &did.Document{ID: *id, Controller: []did.DID{*ctrlID1, *ctrlID2}}
		got, err := am.resolveDIDControllers(nextDoc)
		assert.Empty(t, got)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to resolve document controller: unable to find the did document")
	})
}

type subscriberDocument struct {
	signingKey      jwk.Key
	signingKeyID    string
	signingTime     time.Time
	ref             hash.SHA256Hash
	timelineID      hash.SHA256Hash
	timelineVersion int
	payloadHash     hash.SHA256Hash
	payloadType     string
}

func (s subscriberDocument) SigningKey() jwk.Key {
	return s.signingKey
}

func (s subscriberDocument) SigningKeyID() string {
	return s.signingKeyID
}

func (s subscriberDocument) SigningTime() time.Time {
	return s.signingTime
}

func (s subscriberDocument) Ref() hash.SHA256Hash {
	return s.ref
}

func (s subscriberDocument) TimelineID() hash.SHA256Hash {
	return s.timelineID
}

func (s subscriberDocument) TimelineVersion() int {
	return s.timelineVersion
}

func (s subscriberDocument) PayloadHash() hash.SHA256Hash {
	return s.payloadHash
}


func (s subscriberDocument) PayloadType() string {
	return s.payloadType
}
func (s subscriberDocument) SigningAlgorithm() string {
	panic("implement me")
}

func Test_ambassador_callback(t *testing.T) {
	signingTime := time.Now()
	createdAt := time.Now().Add(-10 * time.Hour * 24)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	timelineID := hash.SHA256Sum([]byte("timeline"))
	ref := hash.SHA256Sum([]byte("ref"))

	newSubscriberDoc := func() subscriberDocument {
		return subscriberDocument{
			signingKeyID:    "",
			signingTime:     signingTime,
			ref:             ref,
			timelineVersion: 0,
			payloadHash:     payloadHash,
			payloadType:     DIDDocumentType,
		}
	}

	newDidDoc := func() (did.Document, jwk.Key, error) {
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.New(pair.PublicKey)
		keyStr, _ := json.Marshal(signingKey)

		kc := &mockKeyCreator{
			t:      t,
			jwkStr: string(keyStr),
		}
		docCreator := NutsDocCreator{keyCreator: kc}
		didDocument, err := docCreator.Create()
		return *didDocument, signingKey, err
	}

	t.Run("create ok - a new document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberDoc()
		subDoc.signingKey = signingKey

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		expectedMetadata := types.DocumentMetadata{
			Created:    signingTime,
			Updated:    nil,
			Version:    0,
			TimelineID: ref,
			Hash:       payloadHash,
		}

		didStoreMock.EXPECT().Write(expectedDocument, expectedMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("create nok - fails without embedded key", func(t *testing.T) {
		am := ambassador{}

		subDoc := subscriberDocument{
			signingKeyID:    "",
			signingTime:     signingTime,
			ref:             ref,
			timelineVersion: 0,
			payloadHash:     payloadHash,
			payloadType:     DIDDocumentType,
		}
		err := am.callback(subDoc, []byte("{}"))
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "callback could not process new DID Document: signingKey for new DID Documents must be set", err.Error())
	})

	t.Run("create nok - fails when signing key is missing from authenticationMethods", func(t *testing.T) {
		am := ambassador{}

		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.New(pair.PublicKey)
		subDoc := newSubscriberDoc()
		subDoc.signingKey = signingKey

		err := am.callback(subDoc, []byte("{}"))
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "key used to sign Network document must be be part of DID Document authentication", err.Error())
	})

	t.Run("update ok - with the exact same document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStore := crypto.NewMockKeyResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStore,
		}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.New(pair.PublicKey)
		keyStr, _ := json.Marshal(signingKey)

		kc := &mockKeyCreator{
			t:      t,
			jwkStr: string(keyStr),
		}
		docCreator := NutsDocCreator{keyCreator: kc}
		didDocument, err := docCreator.Create()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberDoc()
		subDoc.signingKeyID = didDocument.Authentication[0].ID.String()
		subDoc.timelineVersion = 1
		subDoc.timelineID = timelineID
		subDoc.payloadHash = payloadHash

		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created:    createdAt,
			Updated:    nil,
			Version:    0,
			TimelineID: timelineID,
			Hash:       currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:    createdAt,
			Updated:    &signingTime,
			Version:    1,
			TimelineID: timelineID,
			Hash:       payloadHash,
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, &types.ResolveMetadata{}).Times(2).Return(&expectedDocument, currentMetadata, nil)
		keyStore.EXPECT().GetPublicKey(didDocument.Authentication[0].ID.String(), subDoc.signingTime).Return(pair.Public(), nil)
		didStoreMock.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("ok - where the document is not the controller", func(t *testing.T) {
		// the right key should be resolved
	})

	t.Run("ok - update with a new authentication key", func(t *testing.T) {
		// old key should be removed
		// new key should be present

	})

	t.Run("nok - update with missing timelineID", func(t *testing.T) {
		subDoc := newSubscriberDoc()
		subDoc.timelineVersion = 5
		am := ambassador{}
		err := am.callback(subDoc, []byte("{}"))
		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "callback could not process new DID Document: timelineVersion for new documents must be absent or equal to 0")
	})

	t.Run("nok - update of unknown DID Document", func(t *testing.T) {
		subDoc := newSubscriberDoc()
		subDoc.timelineVersion = 5
		subDoc.timelineID = timelineID
		am := ambassador{
			didStore: didStoreMock{ err: types.ErrNotFound },
		}
		err := am.callback(subDoc, []byte("{}"))
		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "unable to update did document: unable to find the did document")
	})

	t.Run("nok - current DID document has different timelineID than the new one", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		am := ambassador{
			didStore:    didStoreMock,
		}

		subDoc := newSubscriberDoc()
		subDoc.timelineVersion = 5
		subDoc.timelineID = timelineID

		// The current DID Document which will be resolved
		currentDIDDocument := did.Document{}

		newDIDDocument, _, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}
		didDocPayload, _ := json.Marshal(newDIDDocument)

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			TimelineID: hash.SHA256Sum([]byte("wrong timeline")),
		}
		didStoreMock.EXPECT().Resolve(newDIDDocument.ID, &types.ResolveMetadata{}).Times(1).Return(&currentDIDDocument, currentMetadata, nil)

		err = am.callback(subDoc, didDocPayload)
		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "timelineIDs of new and current DID documents must match")
	})

	t.Run("nok - update of document with a existing key that is not part of the controller", func(t *testing.T) {

	})

	t.Run("nok - create where keyID of authentication key matches but thumbprints not", func(t *testing.T) {

	})
}
