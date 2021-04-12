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
		assert.Contains(t, err.Error(), "unable to resolve document controller: unable to find the DID document")
	})
}

type subscriberTransaction struct {
	signingKey      jwk.Key
	signingKeyID    string
	signingTime     time.Time
	ref             hash.SHA256Hash
	payloadHash     hash.SHA256Hash
	payloadType     string
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

func Test_ambassador_callback(t *testing.T) {
	signingTime := time.Now()
	createdAt := time.Now().Add(-10 * time.Hour * 24)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newSubscriberDoc := func() subscriberTransaction {
		return subscriberTransaction{
			signingKeyID:    "validKeyID123",
			signingTime:     signingTime,
			ref:             ref,
			payloadHash:     payloadHash,
			payloadType:     didDocumentType,
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
		signingKey.Set(jwk.KeyIDKey, didDocument.Authentication[0].ID.String())
		return *didDocument, signingKey, err
	}

	t.Run("create ok - a new document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberDoc()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = ""

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		expectedMetadata := types.DocumentMetadata{
			Created:    signingTime,
			Updated:    nil,
			Hash:       payloadHash,
		}
		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		keyStoreMock.EXPECT().AddPublicKey(signingKey.KeyID(), rawKey, subDoc.signingTime)
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
		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberDoc()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = ""

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		expectedMetadata := types.DocumentMetadata{
			Created:    signingTime,
			Updated:    nil,
			Hash:       payloadHash,
		}

		keyStoreMock.EXPECT().AddPublicKey(signingKey.KeyID(), rawKey, subDoc.signingTime).Return(crypto.ErrKeyAlreadyExists)
		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		didStoreMock.EXPECT().Write(expectedDocument, expectedMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("nok - error while adding key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStoreMock,
		}

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		subDoc := newSubscriberDoc()
		subDoc.signingKey = signingKey
		subDoc.signingKeyID = ""

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		keyStoreMock.EXPECT().AddPublicKey(signingKey.KeyID(), rawKey, subDoc.signingTime).Return(errors.New("failed"))
		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		err = am.callback(subDoc, didDocPayload)
		assert.Error(t, err)
	})

	t.Run("nok - invalid payload", func(t *testing.T) {
		subDoc := newSubscriberDoc()
		am := ambassador{}
		err := am.callback(subDoc, []byte("}"))
		assert.EqualError(t, err, "unable to unmarshall did document from network payload: invalid character '}' looking for beginning of value")
	})

	t.Run("nok - DID document invalid according to W3C spec", func(t *testing.T) {
		subDoc := newSubscriberDoc()
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
			signingKeyID:    "key-1",
			signingTime:     signingTime,
			ref:             ref,
			payloadHash:     payloadHash,
			payloadType:     didDocumentType,
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
		subDoc := newSubscriberDoc()
		subDoc.signingKeyID = ""
		subDoc.signingKey = signingKey

		doc, _, _ := newDidDoc()
		docBytes, _ := doc.MarshalJSON()

		didStoreMock.EXPECT().Resolve(doc.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		err := am.callback(subDoc, docBytes)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "key used to sign transaction must be be part of DID Document authentication", err.Error())
	})
	t.Run("update ok - with a deactivated document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStore := crypto.NewMockPublicKeyStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStore,
		}
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberDoc()
		subDoc.signingKeyID = didDocument.Authentication[0].ID.String()
		subDoc.payloadHash = payloadHash

		storedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &storedDocument)

		deactivatedDocument := did.Document{Context: []ssi.URI{did.DIDContextV1URI()}, ID: storedDocument.ID}
		didDocPayload, _ = json.Marshal(deactivatedDocument)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created:    createdAt,
			Updated:    nil,
			Hash:       currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:     createdAt,
			Updated:     &signingTime,
			Hash:        payloadHash,
			Deactivated: true,
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(3).Return(&storedDocument, currentMetadata, nil)
		keyStore.EXPECT().GetPublicKey(didDocument.Authentication[0].ID.String(), subDoc.signingTime).Return(pKey, nil)
		keyStore.EXPECT().RevokePublicKey(storedDocument.Authentication[0].ID.String(), gomock.Any())
		didStoreMock.EXPECT().Update(didDocument.ID, currentMetadata.Hash, deactivatedDocument, &expectedNextMetadata)

		err = am.callback(subDoc, didDocPayload)
		assert.NoError(t, err)
	})

	t.Run("update ok - with the exact same document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStore := crypto.NewMockPublicKeyStore(ctrl)

		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStore,
		}
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberDoc()
		subDoc.signingKeyID = didDocument.Authentication[0].ID.String()
		subDoc.payloadHash = payloadHash

		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created:    createdAt,
			Updated:    nil,
			Hash:       currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:    createdAt,
			Updated:    &signingTime,
			Hash:       payloadHash,
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(3).Return(&expectedDocument, currentMetadata, nil)
		keyStore.EXPECT().GetPublicKey(didDocument.Authentication[0].ID.String(), subDoc.signingTime).Return(pKey, nil)
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
		keyStore := crypto.NewMockPublicKeyStore(ctrl)

		// initiate the ambassador with the mocks
		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStore,
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

		// remove any authentication methods from the did document
		didDocument.Authentication = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberDoc()
		subDoc.signingKeyID = didDocumentController.Authentication[0].ID.String()
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
			Created:    createdAt,
			Updated:    nil,
			Hash:       currentPayloadHash,
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:    createdAt,
			Updated:    &signingTime,
			Hash:       payloadHash,
		}

		gomock.InOrder(
			// expect a resolve for previous versions of the did document
			didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil),
			// expect a resolve for the did documents controller
			didStoreMock.EXPECT().Resolve(didDocumentController.ID, nil).Times(1).Return(&expectedController, nil, nil),
		)

		keyStore.EXPECT().GetPublicKey(didDocumentController.Authentication[0].ID.String(), subDoc.signingTime).Return(pKey, nil)
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
		keyStore := crypto.NewMockPublicKeyStore(ctrl)

		// initiate the ambassador with the mocks
		am := ambassador{
			didStore: didStoreMock,
			keyStore: keyStore,
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

		keyID := didDocument.Authentication[0].ID.String()

		// remove any authentication methods from the did document
		didDocument.Authentication = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		subDoc := newSubscriberDoc()
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
			Created:    createdAt,
			Updated:    nil,
			Hash:       currentPayloadHash,
		}

		// expect a resolve for previous versions of the did document
		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Times(2).Return(&expectedDocument, currentMetadata, nil)
		// expect a resolve for the did documents controller
		didStoreMock.EXPECT().Resolve(didDocumentController.ID, nil).Times(1).Return(&expectedController, nil, nil)

		keyStore.EXPECT().GetPublicKey(keyID, subDoc.signingTime).Return(pKey, nil)

		err = am.callback(subDoc, didDocPayload)
		assert.EqualError(t, err, "network document not signed by one of its controllers")
	})

	t.Run("nok - create where keyID of authentication key matches but thumbprints not", func(t *testing.T) {

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
				signingKeyID:    "",
				signingTime:     signingTime,
				signingKey:      signingKey,
				ref:             ref,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			nil,
		},
		{"ok - valid update document",
			subscriberTransaction{
				signingKeyID:    "kid123",
				signingTime:     signingTime,
				ref:             ref,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			nil,
		},
		{"nok - payload rejects invalid payload type",
			subscriberTransaction{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				payloadHash:     payloadHash,
				payloadType:     "application/xml",
			},
			errors.New("wrong payload type for this subscriber. Can handle: application/did+json, got: application/xml"),
		},
		{"nok - missing payload hash",
			subscriberTransaction{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				payloadType:     didDocumentType,
			},
			errors.New("payloadHash must be provided"),
		},
		{"nok - missing signingTime",
			subscriberTransaction{
				signingKeyID:    "",
				signingKey:      signingKey,
				ref:             ref,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
		{"nok - signingTime in the future",
			subscriberTransaction{
				signingKeyID:    "",
				signingTime:     signingTime.Add(10 * time.Minute),
				signingKey:      signingKey,
				ref:             ref,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
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

func newDidDoc(t *testing.T) (did.Document, jwk.Key, error) {
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.New(pair.PublicKey)
	keyStr, _ := json.Marshal(signingKey)

	kc := &mockKeyCreator{
		t:      t,
		jwkStr: string(keyStr),
	}
	docCreator := NutsDocCreator{keyCreator: kc}
	didDocument, err := docCreator.Create()
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
			didDoc, _, _ := newDidDoc(t)
			a.doc = didDoc
		}, nil},
		//
		// Verification methods
		//
		{"nok - verificationMethod ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			didDoc.VerificationMethod[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have a fragment")},
		{"nok - verificationMethod ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			didDoc.VerificationMethod[0].ID.ID = "foo:123"
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have document prefix")},
		{"nok - verificationMethod with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			method := didDoc.VerificationMethod[0]
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, method)
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must be unique")},
		//
		// Services
		//
		{"nok - service with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			svc := didDoc.Service[0]
			didDoc.Service = append(didDoc.Service, svc)
			a.doc = didDoc
		}, errors.New("invalid service: ID must be unique")},
		{"nok - service ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			didDoc.Service[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid service: ID must have a fragment")},
		{"nok - service ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
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

func Test_ambassador_updateKeysInStore(t *testing.T) {
	t.Run("ok - empty documents", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		proposed := did.Document{}

		err := sut.updateKeysInStore(current, proposed, time.Now())
		assert.NoError(t, err,
			"expected no error when providing two empty documents")
	})

	t.Run("ok - one new key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		proposed := did.Document{}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		timeNow := time.Now()
		vm, err := did.NewVerificationMethod(did.DID{}, ssi.JsonWebKey2020, did.DID{}, pair.PublicKey)
		if !assert.NoError(t, err,
			"unexpected error while generating a new verificationMethod") {
			return
		}
		proposed.AddAuthenticationMethod(vm)

		keyStoreMock.EXPECT().AddPublicKey(vm.ID.String(), &pair.PublicKey, timeNow).Return(nil)

		err = sut.updateKeysInStore(current, proposed, timeNow)
		assert.NoError(t, err,
			"expected no error when adding one key")

	})

	t.Run("ok - one old key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		timeNow := time.Now()
		vm, err := did.NewVerificationMethod(did.DID{}, ssi.JsonWebKey2020, did.DID{}, pair.PublicKey)
		if !assert.NoError(t, err,
			"unexpected error while generating a new verificationMethod") {
			return
		}
		current.AddAuthenticationMethod(vm)

		proposed := did.Document{}
		keyStoreMock.EXPECT().RevokePublicKey(vm.ID.String(), timeNow)

		err = sut.updateKeysInStore(current, proposed, timeNow)
		assert.NoError(t, err,
			"expected no error when removing one key")
	})

	t.Run("error - adding key failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		proposed := did.Document{}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		timeNow := time.Now()
		vm, err := did.NewVerificationMethod(did.DID{}, ssi.JsonWebKey2020, did.DID{}, pair.PublicKey)
		if !assert.NoError(t, err,
			"unexpected error while generating a new verificationMethod") {
			return
		}
		proposed.AddAuthenticationMethod(vm)

		keyStoreMock.EXPECT().AddPublicKey(vm.ID.String(), &pair.PublicKey, timeNow).Return(crypto.ErrKeyAlreadyExists)

		err = sut.updateKeysInStore(current, proposed, timeNow)
		assert.EqualError(t, err, "unable to add new public key: key already exists")
	})

	t.Run("ok - revoking already revoked key should succeed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		timeNow := time.Now()
		vm, err := did.NewVerificationMethod(did.DID{}, ssi.JsonWebKey2020, did.DID{}, pair.PublicKey)
		if !assert.NoError(t, err,
			"unexpected error while generating a new verificationMethod") {
			return
		}
		current.AddAuthenticationMethod(vm)

		proposed := did.Document{}
		keyStoreMock.EXPECT().RevokePublicKey(vm.ID.String(), timeNow).Return(crypto.ErrKeyRevoked)

		err = sut.updateKeysInStore(current, proposed, timeNow)
		assert.NoError(t, err)
	})

	t.Run("error - revoking key failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyStoreMock := crypto.NewMockPublicKeyStore(ctrl)

		sut := ambassador{keyStore: keyStoreMock}

		current := did.Document{}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		timeNow := time.Now()
		vm, err := did.NewVerificationMethod(did.DID{}, ssi.JsonWebKey2020, did.DID{}, pair.PublicKey)
		if !assert.NoError(t, err,
			"unexpected error while generating a new verificationMethod") {
			return
		}
		current.AddAuthenticationMethod(vm)

		proposed := did.Document{}
		keyStoreMock.EXPECT().RevokePublicKey(vm.ID.String(), timeNow).Return(crypto.ErrKeyNotFound)

		err = sut.updateKeysInStore(current, proposed, timeNow)
		assert.EqualError(t, err, "unable to revoke public key: key not found")
	})
}
