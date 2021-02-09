package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/network"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const expectedPayloadType = "application/did+json"

func TestVDR_Update(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	didStoreMock := types.NewMockStore(ctrl)
	networkMock := network.NewMockTransactions(ctrl)
	vdr := VDR{
		store:   didStoreMock,
		network: networkMock,
	}
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))
	currentDIDDocument := did.Document{
		ID: *id,
		Controller: []did.DID{*id},
		Authentication: []did.VerificationRelationship{{VerificationMethod: &did.VerificationMethod{ID: *keyID}}},
	}
	nextDIDDocument := did.Document{}
	expectedResolverMetadata := &types.ResolveMetadata{
		Hash:             &currentHash,
		AllowDeactivated: false,
	}
	resolvedMetadata := types.DocumentMetadata{
		TimelineID: hash.SHA256Sum([]byte("timeline")),
		Version:    1,
	}
	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
	networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), nil, gomock.Any(), gomock.Any(), gomock.Any())
	err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
	assert.NoError(t, err)
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
	vm, err := did.NewVerificationMethod(*keyID, did.JsonWebKey2020, did.DID{}, privateKey.PublicKey)
	if !assert.NoError(t, err) {
		return
	}
	nextDIDDocument.AddAuthenticationMethod(vm)

	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didCreator.EXPECT().Create().Return(&nextDIDDocument, nil)
	networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), &privateKey.PublicKey, gomock.Any())
	didDoc, err := vdr.Create()
	assert.NoError(t, err)
	assert.NotNil(t, didDoc)
}

func TestNewVDR(t *testing.T) {
	cfg := Config{}
	vdr := NewVDR(cfg, nil, nil)
	assert.IsType(t, &VDR{}, vdr)
	assert.Equal(t, vdr.config, cfg)
}

func TestVDR_Configure(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := network.NewMockTransactions(ctrl)
	// Make sure configuring VDR subscribes to network
	tx.EXPECT().Subscribe(gomock.Any(), gomock.Any())
	cfg := Config{}
	vdr := NewVDR(cfg, nil, tx)
	err := vdr.Configure(core.ServerConfig{})
	assert.NoError(t, err)
}
