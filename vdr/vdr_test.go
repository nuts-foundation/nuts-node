package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/network"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const expectedPayloadType = "application/did+json"

func TestVDR_Update(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)
		vdr := VDR{
			store:          didStoreMock,
			didDocResolver: doc.Resolver{Store: didStoreMock},
			network:        networkMock,
		}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		expectedPayload, _ := json.Marshal(nextDIDDocument)
		didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), nil, gomock.Any())
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.NoError(t, err)
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)
		vdr := VDR{
			store:          didStoreMock,
			didDocResolver: doc.Resolver{Store: didStoreMock},
			network:        networkMock,
		}
		currentDIDDocument := did.Document{ID: *id}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "the DID document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)
		vdr := VDR{
			store:          didStoreMock,
			didDocResolver: doc.Resolver{Store: didStoreMock},
			network:        networkMock,
		}
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, types.ErrNotFound)
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "unable to find the DID document")
	})

	t.Run("error - document not managed by this node", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)

		vdr := VDR{
			store:          didStoreMock,
			didDocResolver: doc.Resolver{Store: didStoreMock},
			network:        networkMock,
		}
		nextDIDDocument := did.Document{ID: *id}
		currentDIDDocument := nextDIDDocument
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		didStoreMock.EXPECT().Resolve(*id, gomock.Any()).Times(1).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		networkMock.EXPECT().CreateTransaction(gomock.Any(), gomock.Any(), gomock.Any(), nil, gomock.Any()).Return(nil, crypto.ErrKeyNotFound)
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.Error(t, err)
		assert.EqualError(t, err, "DID document not managed by this node")
		assert.True(t, errors.Is(err, types.ErrDIDNotManagedByThisNode),
			"expected ErrDIDNotManagedByThisNode error when the document is not managed by this node")
	})
}
func TestVDR_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	networkMock := network.NewMockTransactions(ctrl)
	didCreator := types.NewMockDocCreator(ctrl)

	vdr := VDR{
		network:       networkMock,
		didDocCreator: didCreator,
	}
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID(id.String() + "#key-1")
	nextDIDDocument := did.Document{ID: *id}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err) {
		return
	}
	vm, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, privateKey.PublicKey)
	if !assert.NoError(t, err) {
		return
	}
	nextDIDDocument.AddCapabilityInvocation(vm)

	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didCreator.EXPECT().Create().Return(&nextDIDDocument, nil)
	networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), &privateKey.PublicKey, gomock.Any())
	didDoc, err := vdr.Create()
	assert.NoError(t, err)
	assert.NotNil(t, didDoc)
}

func TestNewVDR(t *testing.T) {
	cfg := Config{}
	vdr := NewVDR(cfg, nil, nil, nil)
	assert.IsType(t, &VDR{}, vdr)
	assert.Equal(t, vdr.config, cfg)
}

func TestVDR_Configure(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := network.NewMockTransactions(ctrl)
	// Make sure configuring VDR subscribes to network
	tx.EXPECT().Subscribe(gomock.Any(), gomock.Any())
	cfg := Config{}
	vdr := NewVDR(cfg, nil, tx, nil)
	err := vdr.Configure(core.ServerConfig{})
	assert.NoError(t, err)
}

func TestVDR_Diagnostics(t *testing.T) {
	t.Run("ok - no conflicts", func(t *testing.T) {
		s := store.NewMemoryStore()
		vdr := NewVDR(Config{}, nil, nil, s)
		results := vdr.Diagnostics()

		if !assert.Len(t, results, 1) {
			return
		}
		assert.Equal(t, "0", results[0].String())
	})

	t.Run("ok - 1 conflict", func(t *testing.T) {
		s := store.NewMemoryStore()
		vdr := NewVDR(Config{}, nil, nil, s)
		doc := did.Document{ID: *TestDIDA}
		metadata := types.DocumentMetadata{SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), hash.EmptyHash()}}
		s.Write(doc, metadata)
		results := vdr.Diagnostics()

		if !assert.Len(t, results, 1) {
			return
		}
		assert.Equal(t, "1", results[0].String())
	})
}
