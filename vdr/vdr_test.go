package vdr

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const expectedDocumentType = "application/did+json"

func TestVDR_Update(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	didStoreMock := types.NewMockStore(ctrl)
	networkMock := network.NewMockTransactions(ctrl)
	vdr := VDR{
		store:   didStoreMock,
		network: networkMock,
	}
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))
	currentDIDDocument := did.Document{
		Authentication: []did.VerificationRelationship{{VerificationMethod: &did.VerificationMethod{ID: *keyID}}},
	}
	nextDIDDocument := did.Document{}
	expectedResolverMetada := &types.ResolveMetadata{
		Hash:             &currentHash,
		AllowDeactivated: false,
	}
	resolvedMetadata := types.DocumentMetadata{
		TimelineID: hash.SHA256Sum([]byte("timeline")),
		Version:    1,
	}
	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didStoreMock.EXPECT().Resolve(*keyID, expectedResolverMetada).Return(&currentDIDDocument, &resolvedMetadata, nil)
	networkMock.EXPECT().CreateDocument(expectedDocumentType, expectedPayload, keyID.String(), false, gomock.Any(), gomock.Any(), gomock.Any())
	err := vdr.Update(*keyID, currentHash, nextDIDDocument, nil)
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
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	nextDIDDocument := did.Document{
		Authentication: []did.VerificationRelationship{{VerificationMethod: &did.VerificationMethod{ID: *keyID}}},
	}
	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didCreator.EXPECT().Create().Return(&nextDIDDocument, nil)
	networkMock.EXPECT().CreateDocument(expectedDocumentType, expectedPayload, keyID.String(), true, gomock.Any())
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
