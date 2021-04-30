package vdr

import (
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// mockKeyCreator can create new keys based on a predefined key
type mockKeyCreator struct {
	kid string
}

// New uses a predefined ECDSA key and calls the namingFunc to get the kid
func (m *mockKeyCreator) New(_ crypto.KIDNamingFunc) (crypto.Key, error) {
	return crypto.NewTestKey(m.kid), nil
}

type subscriberTransaction struct {
	signingKey   jwk.Key
	signingKeyID string
	signingTime  time.Time
	ref          hash.SHA256Hash
	payloadHash  hash.SHA256Hash
	payloadType  string
	prevs        []hash.SHA256Hash
}

func (s subscriberTransaction) SigningKey() jwk.Key {
	return s.signingKey
}

func (s subscriberTransaction) SigningKeyID() string {
	return s.signingKeyID
}

func (s subscriberTransaction) SigningTime() time.Time {
	return s.signingTime
}

func (s subscriberTransaction) Ref() hash.SHA256Hash {
	return s.ref
}

func (s subscriberTransaction) PayloadHash() hash.SHA256Hash {
	return s.payloadHash
}

func (s subscriberTransaction) PayloadType() string {
	return s.payloadType
}
func (s subscriberTransaction) SigningAlgorithm() string {
	panic("implement me")
}

func (s subscriberTransaction) Previous() []hash.SHA256Hash {
	return s.prevs
}

func (s subscriberTransaction) Version() dag.Version {
	panic("implement me")
}

const signingKeyID = "did:nuts:123#validKeyID123"

func Test_ambassador_callback(t *testing.T) {
	signingTime := time.Now()
	createdAt := time.Now().Add(-10 * time.Hour * 24)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newSubscriberTx := func() subscriberTransaction {
		return subscriberTransaction{
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
		assert.EqualError(t, err, "unable to unmarshall did document from network payload: invalid character '}' looking for beginning of value")
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
		subDoc := subscriberTransaction{
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

	t.Run("create nok - fails when signing key is missing from authenticationMethods", func(t *testing.T) {
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
		assert.Equal(t, "key used to sign transaction must be be part of DID Document capabilityInvocation", err.Error())
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

	t.Run("ok - update of document which is controlled by another did document", func(t *testing.T) {
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

		// remove any CapabilityInvocation methods from the did document
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

	t.Run("nok - update of document which is controlled by another did document which does not have the authentication key", func(t *testing.T) {
		// This test checks if the correct authentication method is used for validating the updated did document.
		// It uses a did document with a controller but uses a different key, the one of the did document itself in this case.

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

		// remove any CapabilityInvocation methods from the did document
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

		// expect a resolve for previous versions of the did document
		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil)
		// expect a resolve for the did documents controller
		resolverMock.EXPECT().ResolveControllers(expectedDocument).Return([]did.Document{didDocumentController}, nil)

		keyStoreMock.EXPECT().ResolvePublicKey(keyID, &subDoc.signingTime).Return(pKey, nil)

		err = am.callback(subDoc, didDocPayload)
		assert.EqualError(t, err, "network document not signed by one of its controllers")
	})

	t.Run("nok - create where keyID of authentication key matches but thumbprints not", func(t *testing.T) {

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

func Test_checkSubscriberDocumentIntegrity(t *testing.T) {
	signingTime := time.Now()
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.New(pair.PublicKey)
	signingKey.Set(jwk.KeyIDKey, "kid123")
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	tests := []struct {
		name      string
		args      dag.SubscriberTransaction
		wantedErr error
	}{
		{"ok - valid create document",
			subscriberTransaction{
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
			subscriberTransaction{
				signingKeyID: "kid123",
				signingTime:  signingTime,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			nil,
		},
		{"nok - payload rejects invalid payload type",
			subscriberTransaction{
				signingKeyID: "",
				signingTime:  signingTime,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  "application/xml",
			},
			errors.New("wrong payload type for this subscriber. Can handle: application/did+json, got: application/xml"),
		},
		{"nok - missing payload hash",
			subscriberTransaction{
				signingKeyID: "",
				signingTime:  signingTime,
				ref:          ref,
				payloadType:  didDocumentType,
			},
			errors.New("payloadHash must be provided"),
		},
		{"nok - missing signingTime",
			subscriberTransaction{
				signingKeyID: "",
				signingKey:   signingKey,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
		{"nok - signingTime in the future",
			subscriberTransaction{
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
			if err := checkSubscriberTransactionIntegrity(tt.args); err != nil || tt.wantedErr != nil {
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
	kc := &mockKeyCreator{signingKeyID}
	docCreator := doc.Creator{KeyStore: kc}
	didDocument, key, err := docCreator.Create(doc.DefaultCreationOptions())
	signingKey, _ := jwk.New(key.Public())
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

func Test_checkDIDDocumentIntegrity(t *testing.T) {

	type args struct {
		doc did.Document
	}
	tests := []struct {
		name      string
		beforeFn  func(t *testing.T, a *args)
		wantedErr error
	}{
		{"ok - valid document", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			a.doc = didDoc
		}, nil},
		//
		// Verification methods
		//
		{"nok - verificationMethod ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have a fragment")},
		{"nok - verificationMethod ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.ID = "foo:123"
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have document prefix")},
		{"nok - verificationMethod with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			method := didDoc.VerificationMethod[0]
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, method)
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must be unique")},
		//
		// Services
		//
		{"nok - service with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			svc := didDoc.Service[0]
			didDoc.Service = append(didDoc.Service, svc)
			a.doc = didDoc
		}, errors.New("invalid service: ID must be unique")},
		{"nok - service ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid service: ID must have a fragment")},
		{"nok - service ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			uri, _ := ssi.ParseURI("did:foo:123#foobar")
			didDoc.Service[0].ID = *uri
			a.doc = didDoc
		}, errors.New("invalid service: ID must have document prefix")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := args{}
			tt.beforeFn(t, &a)
			if err := checkDIDDocumentIntegrity(a.doc); err != nil || tt.wantedErr != nil {
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
