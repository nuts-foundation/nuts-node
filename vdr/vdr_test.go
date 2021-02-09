package vdr

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

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
	currentHash := hash.SHA256Sum([]byte("currentHash"))
	keyID, _ := url.Parse(id.String() + "#key-1")
	currentDIDDocument := did.Document{
		Authentication: []did.VerificationRelationship{{VerificationMethod: &did.VerificationMethod{ID: did.URI{*keyID}}}},
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
	didStoreMock.EXPECT().Resolve(*id, expectedResolverMetada).Return(&currentDIDDocument, &resolvedMetadata, nil)
	networkMock.EXPECT().CreateDocument(didDocumentType, expectedPayload, keyID.String(), false, gomock.Any(), gomock.Any(), gomock.Any())
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
	keyID, _ := url.Parse(id.String() + "#key-1")
	nextDIDDocument := did.Document{
		Authentication: []did.VerificationRelationship{{VerificationMethod: &did.VerificationMethod{ID: did.URI{*keyID}}}},
	}
	expectedPayload, _ := json.Marshal(nextDIDDocument)
	didCreator.EXPECT().Create().Return(&nextDIDDocument, nil)
	networkMock.EXPECT().CreateDocument(didDocumentType, expectedPayload, keyID.String(), true, gomock.Any())
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
