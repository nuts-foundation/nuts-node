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

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did"
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

	t.Run("nok - invalid payload", func(t *testing.T) {
		subDoc := newSubscriberDoc()
		subDoc.timelineID = timelineID
		subDoc.timelineVersion = 1
		am := ambassador{}
		err := am.callback(subDoc, []byte("}"))
		assert.EqualError(t, err, "unable to unmarshall did document from network payload: invalid character '}' looking for beginning of value")
	})

	t.Run("create nok - fails without embedded key", func(t *testing.T) {
		am := ambassador{}

		subDoc := subscriberDocument{
			signingKeyID:    "",
			signingTime:     signingTime,
			ref:             ref,
			timelineVersion: 0,
			payloadHash:     payloadHash,
			payloadType:     didDocumentType,
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
		didDocument, signingKey, err := newDidDoc()
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
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		didStoreMock.EXPECT().Resolve(didDocument.ID, &types.ResolveMetadata{}).Times(2).Return(&expectedDocument, currentMetadata, nil)
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
			didStore: didStoreMock{err: types.ErrNotFound},
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
			didStore: didStoreMock,
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
			TimelineID: timelineID,
			Version:    subDoc.timelineVersion + 1,
		}
		didStoreMock.EXPECT().Resolve(newDIDDocument.ID, &types.ResolveMetadata{}).Times(1).Return(&currentDIDDocument, currentMetadata, nil)

		err = am.callback(subDoc, didDocPayload)
		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "unable to update did document: timeline version of current document is greater or equal to the new version")
	})

	t.Run("nok - update of document with outdated version", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		am := ambassador{
			didStore: didStoreMock,
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

	t.Run("ok - update of document which is controlled by another did document", func(t *testing.T) {
		// setup mocks:
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		didStoreMock := types.NewMockStore(ctrl)
		keyStore := crypto.NewMockKeyResolver(ctrl)

		// initiate the ambassador with the mocks
		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStore,
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
		subDoc.timelineVersion = 1
		subDoc.timelineID = timelineID
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

		// expect a resolve for previous versions of the did document
		didStoreMock.EXPECT().Resolve(didDocument.ID, &types.ResolveMetadata{}).Times(1).Return(&expectedDocument, currentMetadata, nil)
		// expect a resolve for the did documents controller
		didStoreMock.EXPECT().Resolve(didDocumentController.ID, &types.ResolveMetadata{}).Times(1).Return(&expectedController, nil, nil)

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
		keyStore := crypto.NewMockKeyResolver(ctrl)

		// initiate the ambassador with the mocks
		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStore,
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
		subDoc.timelineVersion = 1
		subDoc.timelineID = timelineID
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
			Version:    0,
			TimelineID: timelineID,
			Hash:       currentPayloadHash,
		}

		// expect a resolve for previous versions of the did document
		didStoreMock.EXPECT().Resolve(didDocument.ID, &types.ResolveMetadata{}).Times(1).Return(&expectedDocument, currentMetadata, nil)
		// expect a resolve for the did documents controller
		didStoreMock.EXPECT().Resolve(didDocumentController.ID, &types.ResolveMetadata{}).Times(1).Return(&expectedController, nil, nil)

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
	payloadHash := hash.SHA256Sum([]byte("payload"))
	timelineID := hash.SHA256Sum([]byte("timeline"))
	ref := hash.SHA256Sum([]byte("ref"))

	tests := []struct {
		name      string
		args      dag.SubscriberDocument
		wantedErr error
	}{
		{"ok - valid create document",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				signingKey:      signingKey,
				ref:             ref,
				timelineVersion: 0,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			nil,
		},
		{"ok - valid update document",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				timelineVersion: 1,
				timelineID:      timelineID,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			nil,
		},
		{"nok - payload rejects invalid payload type",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				timelineVersion: 0,
				payloadHash:     payloadHash,
				payloadType:     "application/xml",
			},
			errors.New("wrong payload type for this subscriber. Can handle: application/json+did-document, got: application/xml"),
		},
		{"nok - missing payload hash",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				timelineVersion: 0,
				payloadType:     didDocumentType,
			},
			errors.New("payloadHash must be provided"),
		},
		{"nok - missing signingTime",
			subscriberDocument{
				signingKeyID:    "",
				signingKey:      signingKey,
				ref:             ref,
				timelineVersion: 0,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
		{"nok - signingTime in the future",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime.Add(10 * time.Minute),
				signingKey:      signingKey,
				ref:             ref,
				timelineVersion: 0,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("signingTime must be set and in the past"),
		},
		{
			"nok - create with timelineVersion != 0",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				signingKey:      signingKey,
				ref:             ref,
				timelineVersion: 1,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("timelineVersion for new documents must be absent or equal to 0"),
		},
		{
			"nok - create without embedded signingKey",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				timelineVersion: 0,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("signingKey for new DID Documents must be set"),
		},
		{
			"nok - update with timelineVersion == 0",
			subscriberDocument{
				signingKeyID:    "",
				signingTime:     signingTime,
				ref:             ref,
				timelineVersion: 0,
				timelineID:      timelineID,
				payloadHash:     payloadHash,
				payloadType:     didDocumentType,
			},
			errors.New("timelineVersion for updates must be greater than 0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkSubscriberDocumentIntegrity(tt.args); err != nil || tt.wantedErr != nil {
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
	return *didDocument, signingKey, err
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
		{"nok - validation method has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			didDoc.VerificationMethod[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("verification method must have a fragment")},
		{"nok - validation has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			didDoc.VerificationMethod[0].ID.Opaque = "foo:123"
			a.doc = didDoc
		}, errors.New("verification method must have document prefix")},
		{"nok - validation method with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc(t)
			method := didDoc.VerificationMethod[0]
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, method)
			a.doc = didDoc
		}, errors.New("verification method ID must be unique")},
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
