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
	pal          [][]byte
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

func (s testTransaction) Clock() uint32 {
	panic("implement me")
}

const signingKeyID = "did:nuts:123#validKeyID123"

func Test_ambassador_callback(t *testing.T) {
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
			payloadType:  didDocumentType,
		}
	}

	t.Run("ok - duplicate if skipped", func(t *testing.T) {
		ctx := newMockContext(t)
		didDocument, _, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}
		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)
		tx := newTX()
		txRef := tx.Ref()
		ctx.didStore.EXPECT().Processed(txRef).Return(true, nil)

		err = ctx.ambassador.callback(tx, didDocPayload)

		assert.NoError(t, err)
	})

	t.Run("nok - invalid payload", func(t *testing.T) {
		tx := newTX()
		ctx := newMockContext(t)
		ctx.didStore.EXPECT().Processed(tx.ref).Return(false, nil)

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
		ctx.didStore.EXPECT().Processed(tx.ref).Return(false, nil)

		// Document is missing context
		id, _ := did.ParseDID("did:foo:bar")
		emptyDIDDocument := did.Document{ID: *id}
		didDocumentBytes, _ := emptyDIDDocument.MarshalJSON()

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
			payloadType: didDocumentType,
		}
	}

	newTX := func() testTransaction {
		return testTransaction{
			signingKeyID: signingKeyID,
			signingTime:  signingTime,
			ref:          ref,
			payloadHash:  payloadHash,
			payloadType:  didDocumentType,
		}
	}

	t.Run("create ok", func(t *testing.T) {
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		tx := newCreateTX(signingKey)

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            nil,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}

		t.Run("a new document", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.didStore.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
			ctx.didStore.EXPECT().Write(didDocument, expectedMetadata)

			err = ctx.ambassador.handleCreateDIDDocument(tx, didDocument)

			assert.NoError(t, err)
		})

		t.Run("same document", func(t *testing.T) {
			ctx := newMockContext(t)
			expectedMetadata := types.DocumentMetadata{
				Created:            signingTime,
				Updated:            &signingTime,
				Hash:               payloadHash,
				SourceTransactions: []hash.SHA256Hash{tx.Ref()},
			}
			ctx.didStore.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(&expectedDocument, &expectedMetadata, nil)
			ctx.didStore.EXPECT().Update(didDocument.ID, payloadHash, expectedDocument, &expectedMetadata).Return(nil)

			err = ctx.ambassador.handleCreateDIDDocument(tx, expectedDocument)

			assert.NoError(t, err)
		})
	})

	t.Run("create failed for duplicate transaction", func(t *testing.T) {
		ctx := newMockContext(t)
		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		tx := newCreateTX(signingKey)

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            &signingTime,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		ctx.didStore.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(&expectedDocument, &expectedMetadata, nil)
		ctx.didStore.EXPECT().Update(didDocument.ID, payloadHash, expectedDocument, &expectedMetadata).Return(errors.New("b00m!"))

		err = ctx.ambassador.handleCreateDIDDocument(tx, expectedDocument)

		assert.EqualError(t, err, "unable to register DID document: b00m!")
	})

	// This test recreates the situation where the node gets restarted and the ambassador handles all the
	//   documents it is subscribed at. Since the did store is non-persistent but the keystore is,
	//   many keys will already be in the keyStore. This test checks if the ErrKeyAlreadyExists is handled ok
	t.Run("ok - adding a key which already exists", func(t *testing.T) {
		ctx := newMockContext(t)

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		tx := newCreateTX(signingKey)

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            nil,
			Hash:               payloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}

		ctx.didStore.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		ctx.didStore.EXPECT().Write(didDocument, expectedMetadata)

		err = ctx.ambassador.handleCreateDIDDocument(tx, didDocument)
		assert.NoError(t, err)
	})

	t.Run("create nok - fails when DID does not matches signing key", func(t *testing.T) {
		ctx := newMockContext(t)
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signingKey, _ := jwk.New(pair.PublicKey)
		signingKey.Set(jwk.KeyIDKey, "kid123")
		tx := newTX()
		tx.signingKeyID = ""
		tx.signingKey = signingKey

		doc, _, _ := newDidDoc()

		err := ctx.ambassador.handleCreateDIDDocument(tx, doc)

		if !assert.Error(t, err) {
			return
		}
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
			payloadType:  didDocumentType,
		}
	}

	t.Run("update ok - with a deactivated document", func(t *testing.T) {
		ctx := newMockContext(t)

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

		storedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &storedDocument)

		deactivatedDocument := doc.CreateDocument()
		deactivatedDocument.ID = storedDocument.ID
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
			PreviousHash:       &currentPayloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&storedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(storedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{storedDocument}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(storedDocument.CapabilityInvocation[0].ID.String(), &tx.signingTime).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(storedDocument.ID, currentMetadata.Hash, deactivatedDocument, &expectedNextMetadata)

		err = ctx.ambassador.handleUpdateDIDDocument(tx, deactivatedDocument)
		assert.NoError(t, err)
	})

	t.Run("update ok - with the exact same document", func(t *testing.T) {
		ctx := newMockContext(t)

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

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
			PreviousHash:       &currentPayloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&expectedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(expectedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{expectedDocument}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(didDocument.CapabilityInvocation[0].ID.String(), &tx.signingTime).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

		err = ctx.ambassador.handleUpdateDIDDocument(tx, expectedDocument)
		assert.NoError(t, err)
	})

	t.Run("update ok - with hash based resolution", func(t *testing.T) {
		ctx := newMockContext(t)

		didDocument, signingKey, err := newDidDoc()
		if !assert.NoError(t, err) {
			return
		}

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingTime = types.DIDDocumentResolveEpoch.Add(1 * time.Second)
		tx.signingKeyID = didDocument.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

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
			Updated:            &tx.signingTime,
			Hash:               payloadHash,
			PreviousHash:       &currentPayloadHash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&expectedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(expectedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{expectedDocument}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKey(didDocument.CapabilityInvocation[0].ID.String(), tx.prevs).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

		err = ctx.ambassador.handleUpdateDIDDocument(tx, expectedDocument)
		assert.NoError(t, err)
	})

	t.Run("update ok - where the document is not the controller", func(t *testing.T) {
		ctx := newMockContext(t)

		controllerDoc, signingKey, _ := newDidDoc()
		didDocument, _, _ := newDidDocWithOptions(types.DIDCreationOptions{Controllers: []did.DID{controllerDoc.ID}})

		didDocPayload, _ := json.Marshal(didDocument)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = controllerDoc.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    hash.SHA256Sum([]byte("currentPayloadHash")),
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:            createdAt,
			Updated:            &signingTime,
			Hash:               payloadHash,
			PreviousHash:       &currentMetadata.Hash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&expectedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(expectedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{controllerDoc}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(controllerDoc.CapabilityInvocation[0].ID.String(), &tx.signingTime).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

		err := ctx.ambassador.handleUpdateDIDDocument(tx, expectedDocument)
		assert.NoError(t, err)
	})

	t.Run("update ok - update with a new capabilityInvocation key", func(t *testing.T) {
		ctx := newMockContext(t)

		currentDoc, signingKey, _ := newDidDoc()
		newDoc := did.Document{Context: []ssi.URI{did.DIDContextV1URI()}, ID: currentDoc.ID}
		newCapInv, _ := doc.CreateNewVerificationMethodForDID(currentDoc.ID, &mockKeyCreator{})
		newDoc.AddCapabilityInvocation(newCapInv)

		didDocPayload, _ := json.Marshal(newDoc)
		payloadHash := hash.SHA256Sum(didDocPayload)

		tx := newTX()
		tx.signingKeyID = currentDoc.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

		// This is the metadata of the current version of the document which will be returned by the resolver
		currentMetadata := &types.DocumentMetadata{
			Created: createdAt,
			Updated: nil,
			Hash:    hash.SHA256Sum([]byte("currentPayloadHash")),
		}

		// This is the metadata that will be written during the update
		expectedNextMetadata := types.DocumentMetadata{
			Created:            createdAt,
			Updated:            &signingTime,
			Hash:               payloadHash,
			PreviousHash:       &currentMetadata.Hash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}
		var pKey crypto2.PublicKey
		signingKey.Raw(&pKey)

		ctx.didStore.EXPECT().Resolve(currentDoc.ID, nil).Return(&currentDoc, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(currentDoc, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{currentDoc}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(currentDoc.CapabilityInvocation[0].ID.String(), &tx.signingTime).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(currentDoc.ID, currentMetadata.Hash, newDoc, &expectedNextMetadata)

		err := ctx.ambassador.handleUpdateDIDDocument(tx, newDoc)
		assert.NoError(t, err)
	})

	t.Run("ok - update of document which is controlled by another DID document", func(t *testing.T) {
		// setup mocks:
		ctx := newMockContext(t)

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

		tx := newTX()
		tx.signingKeyID = didDocumentController.CapabilityInvocation[0].ID.String()
		tx.payloadHash = payloadHash

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
			PreviousHash:       &currentMetadata.Hash,
			SourceTransactions: []hash.SHA256Hash{tx.Ref()},
		}

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&expectedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(expectedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{didDocumentController}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(didDocumentController.CapabilityInvocation[0].ID.String(), &tx.signingTime).Return(pKey, nil)
		ctx.didStore.EXPECT().Update(didDocument.ID, currentMetadata.Hash, expectedDocument, &expectedNextMetadata)

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

		tx := newTX()
		tx.signingKeyID = keyID
		tx.payloadHash = payloadHash

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

		ctx.didStore.EXPECT().Resolve(didDocument.ID, nil).Return(&expectedDocument, currentMetadata, nil)
		ctx.resolver.EXPECT().ResolveControllers(expectedDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return([]did.Document{didDocumentController}, nil)
		ctx.keyStore.EXPECT().ResolvePublicKeyInTime(keyID, &tx.signingTime).Return(pKey, nil)

		err = ctx.ambassador.handleUpdateDIDDocument(tx, didDocument)
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

		tx := newTX()
		tx.signingKeyID = signingKey.KeyID()
		tx.signingTime = signingTime

		didDocPayload, _ := json.Marshal(didDocument)
		expectedDocument := did.Document{}
		json.Unmarshal(didDocPayload, &expectedDocument)

		var rawKey crypto2.PublicKey
		signingKey.Raw(&rawKey)

		expectedMetadata := types.DocumentMetadata{
			Created:            signingTime,
			Updated:            &signingTime,
			Hash:               payloadHash,
			PreviousHash:       &didMetadata.Hash,
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), tx.Ref()},
		}

		didStoreMock.EXPECT().Resolve(didDocument.ID, gomock.Any()).Return(&didDocument, &didMetadata, nil)
		keyStoreMock.EXPECT().ResolvePublicKeyInTime(signingKey.KeyID(), gomock.Any()).Return(pKey, nil)
		didStoreMock.EXPECT().Update(didDocument.ID, hash.EmptyHash(), expectedDocument, &expectedMetadata).Return(nil)

		err = am.handleUpdateDIDDocument(tx, expectedDocument)
		assert.NoError(t, err)
	})
}

func Test_sortHashes(t *testing.T) {
	h0 := hash.SHA256Hash{}
	h1 := hash.SHA256Hash{1}
	h2 := hash.SHA256Hash{2}
	input := []hash.SHA256Hash{h2, h0, h1}
	sortHashes(input)
	assert.Equal(t, []hash.SHA256Hash{h0, h1, h2}, input)
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
		tx := testTransaction{signingTime: time.Now()}

		didStoreMock.EXPECT().Resolve(didDocument.ID, nil).Return(&didDocument, &types.DocumentMetadata{}, nil)
		docResolverMock.EXPECT().ResolveControllers(didDocument, &types.ResolveMetadata{ResolveTime: &tx.signingTime}).Return(nil, errors.New("failed"))

		err := am.handleUpdateDIDDocument(&tx, didDocument)
		assert.EqualError(t, err, "unable to resolve DID document's controllers: failed")
	})
}

func Test_checkTransactionIntegrity(t *testing.T) {
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

func Test_uniqueTransactions(t *testing.T) {
	h1 := hash.SHA256Sum([]byte("hash1"))
	h2 := hash.SHA256Sum([]byte("hash2"))

	t.Run("ok - empty list", func(t *testing.T) {
		current := []hash.SHA256Hash{}

		unique := uniqueTransactions(current, h1)

		assert.Len(t, unique, 1)
	})

	t.Run("ok - no overlap", func(t *testing.T) {
		current := []hash.SHA256Hash{h2}

		unique := uniqueTransactions(current, h1)

		assert.Len(t, unique, 2)
	})

	t.Run("ok - duplicates", func(t *testing.T) {
		current := []hash.SHA256Hash{h1, h2}

		unique := uniqueTransactions(current, h1)

		assert.Len(t, unique, 2)
	})
}

func newDidDocWithOptions(opts types.DIDCreationOptions) (did.Document, jwk.Key, error) {
	kc := &mockKeyCreator{}
	docCreator := doc.Creator{KeyStore: kc}
	didDocument, key, err := docCreator.Create(opts)
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

func newDidDoc() (did.Document, jwk.Key, error) {
	return newDidDocWithOptions(doc.DefaultCreationOptions())
}

type mockContext struct {
	ctrl       *gomock.Controller
	didStore   *types.MockStore
	keyStore   *types.MockKeyResolver
	resolver   *types.MockDocResolver
	ambassador ambassador
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	didStoreMock := types.NewMockStore(ctrl)
	keyStoreMock := types.NewMockKeyResolver(ctrl)
	resolverMock := types.NewMockDocResolver(ctrl)
	am := ambassador{
		didStore:    didStoreMock,
		docResolver: resolverMock,
		keyResolver: keyStoreMock,
	}

	return mockContext{
		ctrl:       ctrl,
		didStore:   didStoreMock,
		keyStore:   keyStoreMock,
		resolver:   resolverMock,
		ambassador: am,
	}
}
