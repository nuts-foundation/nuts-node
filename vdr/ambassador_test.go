package vdr

import (
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// mockKeyCreator creates a single new key
type mockKeyCreator struct {
	key crypto.Key
}

// New creates a new valid key with the correct KID
func (m *mockKeyCreator) New(fn crypto.KIDNamingFunc) (crypto.Key, error) {
	if m.key == nil {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		kid, _ := fn(privateKey.Public())

		m.key = &crypto.TestKey{
			PrivateKey: privateKey,
			Kid:        kid,
		}
	}
	return m.key, nil
}

type testTransaction struct {
	signingKey   jwk.Key
	signingKeyID string
	signingTime  time.Time
	ref          hash.SHA256Hash
	payloadHash  hash.SHA256Hash
	payloadType  string
	prevs        []hash.SHA256Hash
}

func (s testTransaction) SigningKey() jwk.Key {
	return s.signingKey
}

func (s testTransaction) SigningKeyID() string {
	return s.signingKeyID
}

func (s testTransaction) SigningTime() time.Time {
	return s.signingTime
}

func (s testTransaction) Ref() hash.SHA256Hash {
	return s.ref
}

func (s testTransaction) PayloadHash() hash.SHA256Hash {
	return s.payloadHash
}

func (s testTransaction) PayloadType() string {
	return s.payloadType
}
func (s testTransaction) SigningAlgorithm() string {
	panic("implement me")
}

func (s testTransaction) Previous() []hash.SHA256Hash {
	return s.prevs
}

func (s testTransaction) Version() dag.Version {
	panic("implement me")
}

func (s testTransaction) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

func (s testTransaction) Data() []byte {
	panic("implement me")
}

const signingKeyID = "did:nuts:123#validKeyID123"

func Test_ambassador_callback(t *testing.T) {
	signingTime := time.Now()
	createdAt := time.Now().Add(-10 * time.Hour * 24)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newSubscriberTx := func() testTransaction {
		return testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  didDocumentType,
		}
	}

	t.Run("create ok - a new document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberTx()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = ""

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            nil,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{subDoc.Ref()},
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		didStoreMock.EXPECT().Write(expectedDocument, expectedMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	// This test recreates the situation where the node gets restarted and the ambassador handles all the
	//   documents it is subscribed at. Since the did store is non-persistent but the keystore is,
	//   many keys will already be in the keyStore. This test checks if the ErrKeyAlreadyExists is handled ok
	t.Run("ok - adding a key which already exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberTx()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = ""

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            nil,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{subDoc.Ref()},
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		didStoreMock.EXPECT().Write(expectedDocument, expectedMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("nok - invalid payload", func(t *testing.T) {
		subDoc := newSubscriberTx()
		am := ambassador{}
		err := am.callback(subDoc, []byte("}"))
		assert.EqualError(t, err, "unable to unmarshal DID document from network payload: invalid character '}' looking for beginning of value")
	})

	t.Run("nok - incorrect payloadType", func(t *testing.T) {
		subDoc := newSubscriberTx()
		subDoc.payloadType = ""
		am := ambassador{}
		err := am.callback(subDoc, []byte{})
		assert.EqualError(t, err, "callback could not process new DID Document: wrong payload type for this subscriber. Can handle: application/did+json, got: ")
	})

	t.Run("nok - DID document invalid according to W3C spec", func(t *testing.T) {
		subDoc := newSubscriberTx()
		am := ambassador{}

		// Document is missing context
		id, _ := did.ParseDID("did:foo:bar")
		emptyDIDDocument := did.Document{ID: *id}
		didDocumentBytes, _ := emptyDIDDocument.MarshalJSON()

		err := am.callback(subDoc, didDocumentBytes)
		assert.True(t, errors.Is(err, did.ErrInvalidContext))
		assert.True(t, errors.Is(err, did.ErrDIDDocumentInvalid))
	})

	t.Run("create nok - fails without embedded key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		am := ambassador{didStore: didStoreMock}

		id, _ := did.ParseDID("did:foo:bar")
		emptyDIDDocument := did.Document{ID: *id, Context: []ssi.URI{did.DIDContextV1URI()}}
		didDocumentBytes, _ := emptyDIDDocument.MarshalJSON()
		subDoc := testTransaction{
			signingKeyID: "key-1",
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  didDocumentType,
		}

		didStoreMock.EXPECT().Resolve(*id, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		err := am.callback(subDoc, didDocumentBytes)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "callback could not process new DID Document: signingKey for new DID Documents must be set", err.Error())
	})

	t.Run("create nok - fails when DID does not matches signing key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		am := ambassador{didStore: didStoreMock}

		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.New(pair.PublicKey)
		signingKey.Set(jwk.KeyIDKey, "kid123")
		subDoc := newSubscriberTx()
		subDoc.signingKeyID = ""
		subDoc.signingKey = signingKey

		doc, _, _ := newDidDoc()
		docBytes, _ := doc.MarshalJSON()

		didStoreMock.EXPECT().Resolve(doc.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		err := am.callback(subDoc, docBytes)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, ErrThumbprintMismatch, err)
	})
	t.Run("update ok - with a deactivated document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)
		resolverMock := types.NewMockDocResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			docResolver: resolverMock,
			keyResolver: keyStoreMock,
		}
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberTx()
		subDoc.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
		subDoc.payloadHash = payloadHash

		storedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &storedDocument)

		deactivatedDocument := did.Document{Context: []ssi.URI{did.DIDContextV1URI()}, ID: storedDocument.ID}
		didDocPayload, _ = json.Marshal(deactivatedDocument)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:            createdAt,
			Updated:            &signingTime,
			Hash:               payloadHash,
			Deactivated:        true,
			SourceTransactions: []hash.SHA256Hash{subDoc.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&storedDocument, currentMetadata, nil)
		resolverMock.EXPECT().ResolveControllers(storedDocument).Return([]did.Document{storedDocument}, nil)
		keyStoreMock.EXPECT().ResolvePublicKey(storedDocument.CapabilityInvocation[0].ID.String(), &subDoc.signingTime).Return(pKey, nil)
		didStoreMock.EXPECT().Update(storedDocument.ID, currentMetadata.Hash, deactivatedDocument, &expectedNextMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("update ok - with the exact same document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)
		resolverMock := types.NewMockDocResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			docResolver: resolverMock,
			keyResolver: keyStoreMock,
		}
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberTx()
		subDoc.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
		subDoc.payloadHash = payloadHash

		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:            createdAt,
			Updated:            &signingTime,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{subDoc.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil)
		resolverMock.EXPECT().ResolveControllers(expectedDocument).Return([]did.Document{expectedDocument}, nil)
		keyStoreMock.EXPECT().ResolvePublicKey(didDocument.CapabilityInvocation[0].ID.String(), &subDoc.signingTime).Return(pKey, nil)
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

	t.Run("ok - update of document which is controlled by another DID document", func(t *testing.T) {
		// setup mocks:
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)
		resolverMock := types.NewMockDocResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			docResolver: resolverMock,
			keyResolver: keyStoreMock,
		}

		// Create a fresh DID Document
		didDocument, _, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		// Create the DID docs controller
		didDocumentController, controllerSigningKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		var pKey crypto2.PublicKey
		controllerSigningKey.Raw(&pKey)

		// set the didDocument`s controller to the controller
		didDocument.Controller = []did.DID{didDocumentController.ID}

		// remove any CapabilityInvocation methods from the DID document
		didDocument.CapabilityInvocation = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberTx()
		subDoc.signingKeyID = didDocumentController.CapabilityInvocation[0].ID.String()
		subDoc.payloadHash = payloadHash

		// Convert back into a fresh doc because that will set the references correct
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		// Convert back into a fresh doc because that will set the references correct
		expectedController := did.Document{}
		json.Unmarshal(didDocControllerPayload, &expectedController)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:            createdAt,
			Updated:            &signingTime,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{subDoc.Ref()},
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil)
		resolverMock.EXPECT().ResolveControllers(expectedDocument).Return([]did.Document{didDocumentController}, nil)
		keyStoreMock.EXPECT().ResolvePublicKey(didDocumentController.CapabilityInvocation[0].ID.String(), &subDoc.signingTime).Return(pKey, nil)
		didStoreMock.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("nok - update of document which is controlled by another DID document which does not have the authentication key", func(t *testing.T) {
		// This test checks if the correct authentication method is used for validating the updated DID document.
		// It uses a DID document with a controller but uses a different key, the one of the DID document itself in this case.

		// setup mocks:
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)
		resolverMock := types.NewMockDocResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			docResolver: resolverMock,
			keyResolver: keyStoreMock,
		}

		// Create a fresh DID Document
		didDocument, documentSigningKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		// Create the DID docs controller
		didDocumentController, _, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		// We still use the document signing key, not the one from the controller
		var pKey crypto2.PublicKey
		documentSigningKey.Raw(&pKey)

		// set the didDocument`s controller to the controller
		didDocument.Controller = []did.DID{didDocumentController.ID}

		keyID := didDocument.CapabilityInvocation[0].ID.String()

		// remove any CapabilityInvocation methods from the DID document
		didDocument.CapabilityInvocation = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberTx()
		subDoc.signingKeyID = keyID
		subDoc.payloadHash = payloadHash

		// Convert back into a fresh doc because that will set the references correct
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		// Convert back into a fresh doc because that will set the references correct
		expectedController := did.Document{}
		json.Unmarshal(didDocControllerPayload, &expectedController)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		// expect a resolve for previous versions of the DID document
		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil)
		// expect a resolve for the DID documents controller
		resolverMock.EXPECT().ResolveControllers(expectedDocument).Return([]did.Document{didDocumentController}, nil)

		keyStoreMock.EXPECT().ResolvePublicKey(keyID, &subDoc.signingTime).Return(pKey, nil)

		err = am.callback(subDoc, didDocPayload)
		assert.EqualError(t, err, "network document not signed by one of its controllers")
	})

	t.Run("ok - updating a DID Document that results in a conflict", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStoreMock,
			docResolver: doc.Resolver{Store: didStoreMock},
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}
		didMetadata := types.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
			Hash:               hash.EmptyHash(),
			Created:            signingTime,
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		subDoc := newSubscriberTx()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = signingKey.KeyID()
		subDoc.signingTime = signingTime

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            &signingTime,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), subDoc.Ref()},
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(&didDocument, &didMetadata, nil).Times(2)
		keyStoreMock.EXPECT().ResolvePublicKey(signingKey.KeyID(), gomock.Any()).Return(pKey, nil)
		didStoreMock.EXPECT().Update(didDocument.ID, hash.EmptyHash(), expectedDocument, &expectedMetadata).Return(nil)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})
}

func Test_handleUpdateDIDDocument(t *testing.T) {
	t.Run("error - unable to resolve controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := types.NewMockKeyResolver(ctrl)
		docResolverMock := types.NewMockDocResolver(ctrl)

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStoreMock,
			docResolver: docResolverMock,
		}

		didDocument, _, _ := newDidDoc()
		tx := testTransaction{}

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Return(&didDocument, &types.DocumentMetadata{}, nil)
		docResolverMock.EXPECT().ResolveControllers(didDocument).Return(nil, errors.New("failed"))

		err := am.handleUpdateDIDDocument(&tx, didDocument)
		assert.EqualError(t, err, "unable to resolve DID document's controllers: failed")
	})
}

func Test_checkSubscriberDocumentIntegrity(t *testing.T) {
	signingTime := time.Now()
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.New(pair.PublicKey)
	signingKey.Set(jwk.KeyIDKey, "kid123")
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	tests := []struct {
		name      string
		args      dag.Transaction
		wantedErr error
	}{
		{"ok - valid create document",
			testTransaction{
				signingKeyID: "",
				signingTime:  signingTime,
				signingKey:   signingKey,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			nil,
		},
		{"ok - valid update document",
			testTransaction{
				signingKeyID: "kid123",
				signingTime:  signingTime,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			nil,
		},
		{"nok - payload rejects invalid payload type",
			testTransaction{
				signingKeyID: "",
				signingTime:  signingTime,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  "application/xml",
			},
			errors.New("wrong payload type for this subscriber. Can handle: application/did+json, got: application/xml"),
		},
		{"nok - missing payload hash",
			testTransaction{
				signingKeyID: "",
				signingTime:  signingTime,
				ref:          ref,
				payloadType:  didDocumentType,
			},
			errors.New("payloadHash must be provided"),
		},
		{"nok - missing signingTime",
			testTransaction{
				signingKeyID: "",
				signingKey:   signingKey,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
		{"nok - signingTime in the future",
			testTransaction{
				signingKeyID: "",
				signingTime:  signingTime.Add(10 * time.Minute),
				signingKey:   signingKey,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkTransactionIntegrity(tt.args); err != nil || tt.wantedErr != nil {
				if err == nil {
					if tt.wantedErr != nil {
						t.Error("expected an error, got nothing")

					}
				} else {
					if tt.wantedErr == nil {

						t.Errorf("unexpected error: %v", err)
					} else {
						if tt.wantedErr.Error() != err.Error() {
							t.Errorf("wrong error\ngot:  %v\nwant: %v", err, tt.wantedErr)
						}
					}
				}
			}
		})
	}
}

func newDidDoc() (did.Document, jwk.Key, error) {
	kc := &mockKeyCreator{}
	docCreator := doc.Creator{KeyStore: kc}
	didDocument, key, err := docCreator.Create(doc.DefaultCreationOptions())
	signingKey, _ := jwk.New(key.Public())
	thumbStr, _ := crypto.Thumbprint(signingKey)
	didStr := fmt.Sprintf("did:nuts:%s", thumbStr)
	id, _ := did.ParseDID(didStr)
	didDocument.ID = *id
	if err != nil {
		return did.Document{}, nil, err
	}
	serviceID := didDocument.ID
	serviceID.Fragment = "1234"
	didDocument.Service = []did.Service{
		{
			ID:              serviceID.URI(),
			Type:            "test",
			ServiceEndpoint: "https://nuts.nl",
		},
	}
	return *didDocument, signingKey, nil
}



func Test_missingTransactions(t *testing.T) {
	h1 := hash.SHA256Sum([]byte("hash1"))
	h2 := hash.SHA256Sum([]byte("hash2"))
	h3 := hash.SHA256Sum([]byte("hash3"))

	t.Run("non-conflicted updated as expected", func(t *testing.T) {
		current := []hash.SHA256Hash{h1}
		incoming := []hash.SHA256Hash{h1, h2}

		diff := missingTransactions(current, incoming)

		assert.Empty(t, diff)
	})

	t.Run("non-conflicted updated without ref", func(t *testing.T) {
		current := []hash.SHA256Hash{h1}
		incoming := []hash.SHA256Hash{h2}

		diff := missingTransactions(current, incoming)

		assert.Len(t, diff, 1)
		assert.Equal(t, current, diff)
	})

	t.Run("conflicted resolved", func(t *testing.T) {
		current := []hash.SHA256Hash{h1, h2}
		incoming := []hash.SHA256Hash{h1, h2, h3}

		diff := missingTransactions(current, incoming)

		assert.Empty(t, diff)
	})
}
