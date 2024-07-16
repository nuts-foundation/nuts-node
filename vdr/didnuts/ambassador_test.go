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
 *
 */

package didnuts

import (
	"context"
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// mockKeyStore creates a single new key
type mockKeyStore struct {
	key crypto.Key
}

// New creates a new valid key with the correct KID
func (m *mockKeyStore) New(_ context.Context, fn crypto.KIDNamingFunc) (crypto.Key, error) {
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

func (m *mockKeyStore) Decrypt(ctx context.Context, kid string, ciphertext []byte) ([]byte, error) {
	panic("not implemented")
}

func (m *mockKeyStore) EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error) {
	panic("not implemented")
}

func (m *mockKeyStore) DecryptJWE(ctx context.Context, message string) (body []byte, headers map[string]interface{}, err error) {
	panic("not implemented")
}

func (m *mockKeyStore) Exists(ctx context.Context, kid string) (bool, error) {
	panic("not implemented")
}

func (m *mockKeyStore) Resolve(ctx context.Context, kid string) (crypto.Key, error) {
	return m.key, nil
}

func (m *mockKeyStore) List(ctx context.Context) []string {
	panic("not implemented")
}

func (m *mockKeyStore) SignJWT(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}, key interface{}) (string, error) {
	panic("not implemented")
}

func (m *mockKeyStore) SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, key interface{}, detached bool) (string, error) {
	panic("not implemented")
}

func (m *mockKeyStore) SignDPoP(ctx context.Context, token dpop.DPoP, kid string) (string, error) {
	panic("not implemented")
}

func (m *mockKeyStore) Delete(ctx context.Context, kid string) error {
	panic("not implemented")
}

type testTransaction struct {
	clock        uint32
	signingKey   jwk.Key
	signingKeyID string
	signingTime  time.Time
	ref          hash.SHA256Hash
	payloadHash  hash.SHA256Hash
	payloadType  string
	prevs        []hash.SHA256Hash
	pal          [][]byte
	data         []byte
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

func (s testTransaction) PAL() [][]byte {
	return s.pal
}

func (s testTransaction) PayloadHash() hash.SHA256Hash {
	return s.payloadHash
}

func (s testTransaction) PayloadType() string {
	return s.payloadType
}
func (s testTransaction) SigningAlgorithm() string {
	panic("not implemented")
}

func (s testTransaction) Previous() []hash.SHA256Hash {
	return s.prevs
}

func (s testTransaction) Version() dag.Version {
	panic("not implemented")
}

func (s testTransaction) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

func (s testTransaction) Data() []byte {
	return s.data
}

func (s testTransaction) Clock() uint32 {
	return s.clock
}

const signingKeyID = "did:nuts:123#validKeyID123"

func TestAmbassador_Start(t *testing.T) {
	t.Run("error on network subscription", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.network.EXPECT().WithPersistency()
		ctx.network.EXPECT().Subscribe("vdr", gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error"))

		err := ctx.ambassador.Start()

		assert.EqualError(t, err, "error")
	})

	t.Run("error on stream subscription", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.network.EXPECT().WithPersistency()
		ctx.network.EXPECT().Subscribe("vdr", gomock.Any(), gomock.Any(), gomock.Any())
		mockPool := events.NewMockConnectionPool(ctx.ctrl)
		mockConnection := events.NewMockConn(ctx.ctrl)
		ctx.eventManager.EXPECT().Pool().Return(mockPool)
		mockPool.EXPECT().Acquire(gomock.Any()).Return(mockConnection, nil, nil)
		mockConnection.EXPECT().JetStream().Return(nil, errors.New("b00m!"))

		err := ctx.ambassador.Start()

		assert.EqualError(t, err, "failed to subscribe to REPROCESS event stream: b00m!")
	})

	t.Run("error on nats connection acquire", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.network.EXPECT().WithPersistency()
		ctx.network.EXPECT().Subscribe("vdr", gomock.Any(), gomock.Any(), gomock.Any())
		mockPool := events.NewMockConnectionPool(ctx.ctrl)
		ctx.eventManager.EXPECT().Pool().Return(mockPool)
		mockPool.EXPECT().Acquire(gomock.Any()).Return(nil, nil, errors.New("b00m!"))

		err := ctx.ambassador.Start()

		assert.EqualError(t, err, "failed to subscribe to REPROCESS event stream: b00m!")
	})
}

func TestAmbassador_handleReprocessEvent(t *testing.T) {
	// going any deeper with unit tests is useless since Nats does not contain any interfaces, just types
	t.Run("ack fails", func(t *testing.T) {
		ctx := newMockContext(t)
		twp := events.TransactionWithPayload{
			Transaction: testTransaction{},
			Payload:     []byte("payload"),
		}
		twpJson, _ := json.Marshal(twp)

		ctx.ambassador.handleReprocessEvent(&nats.Msg{Data: twpJson})
	})
}

func TestAmbassador_handleNetworkEvent(t *testing.T) {
	t.Run("nok - incorrect payloadType", func(t *testing.T) {
		tx := testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  time.Unix(1628000000, 0),
			ref:          hash.SHA256Sum([]byte("ref")),
			payloadHash:  hash.SHA256Sum([]byte("payload")),
			payloadType:  DIDDocumentType,
		}
		tx.payloadType = ""
		am := ambassador{}
		value, err := am.handleNetworkEvent(dag.Event{Transaction: tx})
		assert.False(t, value)
		assert.True(t, errors.As(err, new(dag.EventFatal)))
		assert.EqualError(t, err, "could not process new DID Document: wrong payload type for this subscriber. Can handle: application/did+json, got: ")
	})
}

func TestAmbassador_callback(t *testing.T) {
	// tests based upon time based resolvement of DID documents
	signingTime := time.Unix(1628000000, 0)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newTX := func() testTransaction {
		return testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  DIDDocumentType,
		}
	}

	t.Run("nok - invalid payload", func(t *testing.T) {
		tx := newTX()
		ctx := newMockContext(t)

		err := ctx.ambassador.callback(tx, []byte("}"))

		assert.EqualError(t, err, "unable to unmarshal DID document from network payload: invalid character '}' looking for beginning of value")
	})

	t.Run("nok - incorrect payloadType", func(t *testing.T) {
		tx := newTX()
		tx.payloadType = ""
		am := ambassador{}
		err := am.callback(tx, []byte{})
		assert.EqualError(t, err, "could not process new DID Document: wrong payload type for this subscriber. Can handle: application/did+json, got: ")
	})

	t.Run("nok - DID document invalid according to W3C spec", func(t *testing.T) {
		tx := newTX()
		ctx := newMockContext(t)

		// Document is missing context
		id, _ := did.ParseDID("did:foo:bar")
		emptyDIDDocument := did.Document{ID: *id}
		didDocumentBytes, _ := json.Marshal(emptyDIDDocument)

		err := ctx.ambassador.callback(tx, didDocumentBytes)

		assert.True(t, errors.Is(err, did.ErrInvalidContext))
		assert.True(t, errors.Is(err, did.ErrDIDDocumentInvalid))
	})
}

func TestAmbassador_handleCreateDIDDocument(t *testing.T) {
	// tests based upon time based resolvement of DID documents
	signingTime := time.Unix(1628000000, 0)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newCreateTX := func(signingKey jwk.Key) testTransaction {
		return testTransaction{
			signingKey:  signingKey,
			signingTime: signingTime,
			ref:         ref,
			payloadHash: payloadHash,
			payloadType: DIDDocumentType,
		}
	}

	newTX := func() testTransaction {
		return testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  DIDDocumentType,
		}
	}

	t.Run("create ok", func(t *testing.T) {
		didDocument, signingKey, err := newDidDoc()
		require.NoError(t, err)

		tx := newCreateTX(signingKey)

		t.Run("a new document", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.didStore.EXPECT().Add(didDocument, toStoreTX(tx)).Return(nil)

			err = ctx.ambassador.handleCreateDIDDocument(tx, didDocument)

			assert.NoError(t, err)
		})
	})

	t.Run("create failed", func(t *testing.T) {
		ctx := newMockContext(t)
		didDocument, signingKey, err := newDidDoc()
		require.NoError(t, err)

		tx := newCreateTX(signingKey)

		ctx.didStore.EXPECT().Add(didDocument, toStoreTX(tx)).Return(errors.New("b00m!"))

		err = ctx.ambassador.handleCreateDIDDocument(tx, didDocument)

		assert.EqualError(t, err, "unable to register DID document: b00m!")
	})

	t.Run("create nok - fails when DID does not matches signing key", func(t *testing.T) {
		ctx := newMockContext(t)
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.FromRaw(pair.PublicKey)
		_ = signingKey.Set(jwk.KeyIDKey, "kid123")
		tx := newTX()
		tx.signingKeyID = ""
		tx.signingKey = signingKey

		doc, _, _ := newDidDoc()

		err := ctx.ambassador.handleCreateDIDDocument(tx, doc)

		assert.Equal(t, ErrThumbprintMismatch, err)
	})
}

func TestAmbassador_handleUpdateDIDDocument(t *testing.T) {
	// tests based upon time based resolvement of DID documents
	signingTime := time.Unix(1628000000, 0)
	createdAt := signingTime.Add(-10 * time.Hour * 24)
	payloadHash := hash.SHA256Sum([]byte("payload"))
	ref := hash.SHA256Sum([]byte("ref"))

	newTX := func() testTransaction {
		return testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  DIDDocumentType,
		}
	}

	t.Run("update ok - with a deactivated document", func(t *testing.T) {
		ctx := newMockContext(t)

		didDocument, signingKey, err := newDidDoc()
		require.NoError(t, err)

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		storedDocument := did.Document{}
		_ = json.Unmarshal(didDocPayload, &storedDocument)

		deactivatedDocument := CreateDocument()
		deactivatedDocument.ID = storedDocument.ID

		t.Run("deactivation", func(t *testing.T) {
			tx := newTX()
			tx.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
			tx.payloadHash = payloadHash

			currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

			// This is the metadata of the current version of the document which will be returned by the resolver
			currentMetadata := &resolver.DocumentMetadata{
				Created: createdAt,
				Updated: nil,
				Hash:    currentPayloadHash,
			}

			var pKey crypto2.PublicKey
			_ = signingKey.Raw(&pKey)

			ctx.didStore.EXPECT().Resolve(didDocument.ID, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&storedDocument, currentMetadata, nil)
			ctx.keyResolver.EXPECT().ResolvePublicKey(storedDocument.CapabilityInvocation[0].ID.String(), gomock.Any()).Return(pKey, nil)
			ctx.didStore.EXPECT().Add(deactivatedDocument, toStoreTX(tx))

			err = ctx.ambassador.handleUpdateDIDDocument(tx, deactivatedDocument)

			assert.NoError(t, err)
		})
	})

	t.Run("update ok - update with a new capabilityInvocation key", func(t *testing.T) {
		ctx := newMockContext(t)

		currentDoc, signingKey, _ := newDidDoc()
		newDoc := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: currentDoc.ID}
		newCapInv, _ := CreateNewVerificationMethodForDID(audit.TestContext(), currentDoc.ID, &mockKeyStore{})
		newDoc.AddCapabilityInvocation(newCapInv)

		didDocPayload, _ := json.Marshal(newDoc)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = currentDoc.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash
		prev := hash.RandomHash()
		tx.prevs = []hash.SHA256Hash{prev}

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &resolver.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    hash.SHA256Sum([]byte("currentPayloadHash")),
		}

		var pKey crypto2.PublicKey
		_ = signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(currentDoc.ID, &resolver.ResolveMetadata{AllowDeactivated: true, SourceTransaction: &prev}).Return(&currentDoc, currentMetadata, nil)
		ctx.keyResolver.EXPECT().ResolvePublicKey(currentDoc.CapabilityInvocation[0].ID.String(), gomock.Any()).Return(pKey, nil)
		ctx.didStore.EXPECT().Add(newDoc, toStoreTX(tx))

		err := ctx.ambassador.handleUpdateDIDDocument(tx, newDoc)
		assert.NoError(t, err)
	})

	t.Run("update ok - using 2nd prev for document resolution", func(t *testing.T) {
		ctx := newMockContext(t)

		currentDoc, signingKey, _ := newDidDoc()
		newDoc := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: currentDoc.ID}
		newCapInv, _ := CreateNewVerificationMethodForDID(audit.TestContext(), currentDoc.ID, &mockKeyStore{})
		newDoc.AddCapabilityInvocation(newCapInv)

		didDocPayload, _ := json.Marshal(newDoc)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = currentDoc.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash
		prev := hash.RandomHash()
		tx.prevs = []hash.SHA256Hash{hash.RandomHash(), prev}

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &resolver.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    hash.SHA256Sum([]byte("currentPayloadHash")),
		}

		var pKey crypto2.PublicKey
		_ = signingKey.Raw(&pKey)

		gomock.InOrder(
			ctx.didStore.EXPECT().Resolve(currentDoc.ID, gomock.Any()).Return(nil, nil, resolver.ErrNotFound),
			ctx.didStore.EXPECT().Resolve(currentDoc.ID, &resolver.ResolveMetadata{AllowDeactivated: true, SourceTransaction: &prev}).Return(&currentDoc, currentMetadata, nil),
		)
		ctx.keyResolver.EXPECT().ResolvePublicKey(currentDoc.CapabilityInvocation[0].ID.String(), gomock.Any()).Return(pKey, nil)
		ctx.didStore.EXPECT().Add(newDoc, toStoreTX(tx))

		err := ctx.ambassador.handleUpdateDIDDocument(tx, newDoc)
		assert.NoError(t, err)
	})

	t.Run("ok - update of document which is controlled by another DID document", func(t *testing.T) {
		// setup mocks:
		ctx := newMockContext(t)

		// Create a fresh DID Document
		didDocument, _, err := newDidDoc()
		require.NoError(t, err)

		// Create the DID docs controller
		didDocumentController, controllerSigningKey, err := newDidDoc()
		require.NoError(t, err)

		var pKey crypto2.PublicKey
		_ = controllerSigningKey.Raw(&pKey)

		// set the didDocument`s controller to the controller
		didDocument.Controller = []did.DID{didDocumentController.ID}

		// remove any CapabilityInvocation methods from the DID document
		didDocument.CapabilityInvocation = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = didDocumentController.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

		// Convert back into a fresh doc because that will set the references correct
		expectedDocument := did.Document{}
		_ = json.Unmarshal(didDocPayload, &expectedDocument)

		// Convert back into a fresh doc because that will set the references correct
		expectedController := did.Document{}
		_ = json.Unmarshal(didDocControllerPayload, &expectedController)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &resolver.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		ctx.didStore.EXPECT().Resolve(didDocument.ID, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&expectedDocument, currentMetadata, nil)
		ctx.didResolver.EXPECT().Resolve(didDocumentController.ID, gomock.Any()).Return(&didDocumentController, currentMetadata, nil)
		ctx.keyResolver.EXPECT().ResolvePublicKey(didDocumentController.CapabilityInvocation[0].ID.String(), gomock.Any()).Return(pKey, nil)
		ctx.didStore.EXPECT().Add(expectedDocument, toStoreTX(tx))

		err = ctx.ambassador.handleUpdateDIDDocument(tx, expectedDocument)
		assert.NoError(t, err)
	})

	t.Run("nok - update of document which is controlled by another DID document which does not have the capabilityInvocation key", func(t *testing.T) {
		// This test checks if the correct authentication method is used for validating the updated DID document.
		// It uses a DID document with a controller but uses a different key, the one of the DID document itself in this case.

		// setup mocks:
		ctx := newMockContext(t)

		// Create a fresh DID Document
		didDocument, documentSigningKey, err := newDidDoc()
		require.NoError(t, err)

		// Create the DID docs controller
		didDocumentController, _, err := newDidDoc()
		require.NoError(t, err)

		// We still use the document signing key, not the one from the controller
		var pKey crypto2.PublicKey
		_ = documentSigningKey.Raw(&pKey)

		// set the didDocument`s controller to the controller
		didDocument.Controller = []did.DID{didDocumentController.ID}

		keyID := didDocument.CapabilityInvocation[0].ID.String()

		// remove any CapabilityInvocation methods from the DID document
		didDocument.CapabilityInvocation = nil

		didDocPayload, _ := json.Marshal(didDocument)
		didDocControllerPayload, _ := json.Marshal(didDocumentController)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = keyID
		tx.payloadHash = payloadHash

		// Convert back into a fresh doc because that will set the references correct
		expectedDocument := did.Document{}
		_ = json.Unmarshal(didDocPayload, &expectedDocument)

		// Convert back into a fresh doc because that will set the references correct
		expectedController := did.Document{}
		_ = json.Unmarshal(didDocControllerPayload, &expectedController)

		currentPayloadHash := hash.SHA256Sum([]byte("currentPayloadHash"))

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &resolver.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    currentPayloadHash,
		}

		ctx.didStore.EXPECT().Resolve(didDocument.ID, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&expectedDocument, currentMetadata, nil)
		ctx.didResolver.EXPECT().Resolve(didDocumentController.ID, gomock.Any()).Return(&didDocumentController, currentMetadata, nil)
		ctx.keyResolver.EXPECT().ResolvePublicKey(keyID, gomock.Any()).Return(pKey, nil)

		err = ctx.ambassador.handleUpdateDIDDocument(tx, didDocument)
		assert.EqualError(t, err, "network document not signed by one of its controllers")
	})
}

func Test_handleUpdateDIDDocument(t *testing.T) {
	t.Run("error - unable to resolve controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		didStoreMock := didstore.NewMockStore(ctrl)
		keyStoreMock := resolver.NewMockNutsKeyResolver(ctrl)
		didResolver := &Resolver{Store: didStoreMock}

		am := ambassador{
			didStore:    didStoreMock,
			keyResolver: keyStoreMock,
			didResolver: didResolver,
		}

		didDocument, _, _ := newDidDoc()
		didDocumentController, _, _ := newDidDoc()
		didDocument.Controller = []did.DID{didDocumentController.ID}
		tx := testTransaction{signingTime: time.Now()}

		didStoreMock.EXPECT().Resolve(didDocument.ID, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&didDocument, &resolver.DocumentMetadata{}, nil)
		didStoreMock.EXPECT().Resolve(didDocumentController.ID, gomock.Any()).Return(nil, nil, errors.New("failed"))

		err := am.handleUpdateDIDDocument(&tx, didDocument)
		assert.EqualError(t, err, "unable to resolve DID document's controllers: unable to resolve controller ref: failed")
	})
}

func Test_checkTransactionIntegrity(t *testing.T) {
	signingTime := time.Now()
	pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.FromRaw(pair.PublicKey)
	_ = signingKey.Set(jwk.KeyIDKey, "kid123")
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
				payloadType:  DIDDocumentType,
			},
			nil,
		},
		{"ok - valid update document",
			testTransaction{
				signingKeyID: "kid123",
				signingTime:  signingTime,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  DIDDocumentType,
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
				payloadType:  DIDDocumentType,
			},
			errors.New("payloadHash must be provided"),
		},
		{"nok - missing signingTime",
			testTransaction{
				signingKeyID: "",
				signingKey:   signingKey,
				ref:          ref,
				payloadHash:  payloadHash,
				payloadType:  DIDDocumentType,
			},
			errors.New("signingTime must be set"),
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
	kc := &mockKeyStore{}
	docCreator := Manager{keyStore: kc}
	didDocument, key, err := docCreator.create(audit.TestContext(), DefaultKeyFlags())
	signingKey, _ := jwk.FromRaw(key.Public())
	thumbStr, _ := crypto.Thumbprint(signingKey)
	didDocument.ID = did.MustParseDID(fmt.Sprintf("did:nuts:%s", thumbStr))
	if err != nil {
		return did.Document{}, nil, err
	}
	serviceID := did.DIDURL{DID: didDocument.ID}
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

type mockContext struct {
	ctrl         *gomock.Controller
	didStore     *didstore.MockStore
	keyResolver  *resolver.MockNutsKeyResolver
	didResolver  *resolver.MockDIDResolver
	eventManager *events.MockEvent
	network      *network.MockTransactions
	ambassador   ambassador
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	storeMock := didstore.NewMockStore(ctrl)
	keyResolverMock := resolver.NewMockNutsKeyResolver(ctrl)
	resolverMock := resolver.NewMockDIDResolver(ctrl)
	eventManager := events.NewMockEvent(ctrl)
	networkMock := network.NewMockTransactions(ctrl)
	am := ambassador{
		didStore:      storeMock,
		didResolver:   resolverMock,
		keyResolver:   keyResolverMock,
		eventManager:  eventManager,
		networkClient: networkMock,
	}

	return mockContext{
		ctrl:         ctrl,
		didStore:     storeMock,
		keyResolver:  keyResolverMock,
		didResolver:  resolverMock,
		ambassador:   am,
		eventManager: eventManager,
		network:      networkMock,
	}
}

func toStoreTX(transaction dag.Transaction) didstore.Transaction {
	return didstore.Transaction{
		Clock:       transaction.Clock(),
		PayloadHash: transaction.PayloadHash(),
		Previous:    transaction.Previous(),
		Ref:         transaction.Ref(),
		SigningTime: transaction.SigningTime(),
	}
}
