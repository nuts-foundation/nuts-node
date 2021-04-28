package vdr

import (
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

// testCtx contains the controller and mocks needed fot testing the DocUpdater
type vdrTestCtx struct {
	ctrl         *gomock.Controller
	vdr          types.VDR
	mockStore    *types.MockStore
	mockNetwork  *network.MockTransactions
	mockKeyStore *crypto.MockKeyStore
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := types.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	mockKeyStore := crypto.NewMockKeyStore(ctrl)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	vdr := VDR{
		store:          mockStore,
		didDocResolver: doc.Resolver{Store: mockStore},
		network:        mockNetwork,
		keyStore:       mockKeyStore,
		didDocCreator:  doc.Creator{KeyStore: mockKeyStore},
	}
	return vdrTestCtx{
		ctrl:         ctrl,
		vdr:          vdr,
		mockStore:    mockStore,
		mockNetwork:  mockNetwork,
		mockKeyStore: mockKeyStore,
	}
}

func TestVDR_Update(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		expectedPayload, _ := json.Marshal(nextDIDDocument)
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		ctx.mockKeyStore.EXPECT().Signer(keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, gomock.Any(), false, gomock.Any(), gomock.Any())

		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)

		assert.NoError(t, err)
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		currentDIDDocument := did.Document{ID: *id}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "the DID document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, types.ErrNotFound)
		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "unable to find the DID document")
	})

	t.Run("error - document not managed by this node", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		nextDIDDocument := did.Document{ID: *id}
		currentDIDDocument := nextDIDDocument
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockStore.EXPECT().Resolve(*id, gomock.Any()).Times(1).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		ctx.mockKeyStore.EXPECT().Signer(keyID.String()).Return(nil, crypto.ErrKeyNotFound)

		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "DID document not managed by this node")
		assert.True(t, errors.Is(err, types.ErrDIDNotManagedByThisNode),
			"expected ErrDIDNotManagedByThisNode error when the document is not managed by this node")
	})
}
func TestVDR_Create(t *testing.T) {
	ctx := newVDRTestCtx(t)
	key := crypto.NewTestKey("did:nuts:123#key-1")
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID(key.KID())
	nextDIDDocument := did.Document{Context: []ssi.URI{did.DIDContextV1URI()}, ID: *id}
	vm, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
	if !assert.NoError(t, err) {
		return
	}
	nextDIDDocument.AddCapabilityInvocation(vm)
	nextDIDDocument.AddAssertionMethod(vm)
	expectedPayload, _ := json.Marshal(nextDIDDocument)

	ctx.mockKeyStore.EXPECT().New(gomock.Any()).Return(key, nil)
	ctx.mockNetwork.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, key, true, gomock.Any(), gomock.Any())

	didDoc, err := ctx.vdr.Create(doc.DefaultCreationOptions())

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
