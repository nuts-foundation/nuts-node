package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
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
			store:   didStoreMock,
			network: networkMock,
		}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddAuthenticationMethod(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
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
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)
		vdr := VDR{
			store:   didStoreMock,
			network: networkMock,
		}
		currentDIDDocument := did.Document{ID: *id}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{
			TimelineID: hash.SHA256Sum([]byte("timeline")),
			Version:    1,
		}
		didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "the document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		didStoreMock := types.NewMockStore(ctrl)
		networkMock := network.NewMockTransactions(ctrl)
		vdr := VDR{
			store:   didStoreMock,
			network: networkMock,
		}
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		didStoreMock.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, types.ErrNotFound)
		err := vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "unable to find the did document")
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

func TestVDR_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	didStoreMock := types.NewMockStore(ctrl)
	networkMock := network.NewMockTransactions(ctrl)
	vdr := VDR{
		store:   didStoreMock,
		network: networkMock,
	}

	expectedDocument := did.Document{ID: *id, Context: []did.URI{did.DIDContextV1URI()}}
	expectedPayload, _ := json.Marshal(expectedDocument)

	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddAuthenticationMethod(&did.VerificationMethod{ID: *keyID})

	networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), nil, gomock.Any(), gomock.Any(), gomock.Any())
	gomock.InOrder(
		didStoreMock.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil),
		didStoreMock.EXPECT().Resolve(*id, &types.ResolveMetadata{Hash: &currentHash, AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil),
	)

	err := vdr.Deactivate(*id)
	if !assert.NoError(t, err) {
		return
	}
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

func TestVDR_resolveControllers(t *testing.T) {
	type fields struct {
		config            Config
		store             types.Store
		network           network.Transactions
		OnChange          func(registry *VDR)
		networkAmbassador Ambassador
		_logger           *logrus.Entry
		didDocCreator     types.DocCreator
		keyStore          crypto.KeyStore
	}
	type args struct {
		input []did.Document
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []did.Document
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &VDR{
				config:            tt.fields.config,
				store:             tt.fields.store,
				network:           tt.fields.network,
				OnChange:          tt.fields.OnChange,
				networkAmbassador: tt.fields.networkAmbassador,
				_logger:           tt.fields._logger,
				didDocCreator:     tt.fields.didDocCreator,
				keyStore:          tt.fields.keyStore,
			}
			got, err := r.resolveControllers(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveControllers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("resolveControllers() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVDR_resolveControllers1(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method1, _ := did.ParseDID("did:nuts:123#method-1")
	id456, _ := did.ParseDID("did:nuts:456")
	id456Method1, _ := did.ParseDID("did:nuts:456#method-1")
	t.Run("emtpy input", func(t *testing.T) {
		sut := VDR{}
		docs, err := sut.resolveControllers([]did.Document{})
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list")
	})

	t.Run("doc is its own controller", func(t *testing.T) {
		sut := VDR{}
		doc := did.Document{ID: *id123}
		doc.AddAuthenticationMethod(&did.VerificationMethod{ID: *id123Method1})
		docs, err := sut.resolveControllers([]did.Document{doc})
		assert.NoError(t, err)
		assert.Len(t, docs, 1,
			"expected the document")
		assert.Equal(t, doc, docs[0])
	})

	t.Run("doc is deactivated", func(t *testing.T) {
		sut := VDR{}
		doc := did.Document{ID: *id123}
		docs, err := sut.resolveControllers([]did.Document{doc})
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list when the document is deactivated")
	})

	t.Run("docA is controller of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		sut := VDR{store: store}
		docA := did.Document{ID: *id123}
		docA.AddAuthenticationMethod(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := sut.resolveControllers([]did.Document{docB})
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("docA and docB are both the controllers of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		sut := VDR{store: store}
		docA := did.Document{ID: *id123}
		docA.AddAuthenticationMethod(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123, *id456}}
		docB.AddAuthenticationMethod(&did.VerificationMethod{ID: *id456Method1})

		docs, err := sut.resolveControllers([]did.Document{docB})
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Equal(t, []did.Document{docB, docA}, docs,
			"expected docA and docB to be resolved as controller of docB")
	})

	t.Run("docA is controller of docB, docA has explicit self link in Controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		sut := VDR{store: store}
		docA := did.Document{ID: *id123, Controller: []did.DID{*id123}}
		docA.AddAuthenticationMethod(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := sut.resolveControllers([]did.Document{docB})
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("error - Resolve can not find the document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		sut := VDR{store: store}
		store.EXPECT().Resolve(*id123, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := sut.resolveControllers([]did.Document{docB})
		assert.EqualError(t, err, "unable to resolve controllers: unable to find the did document")
		assert.Len(t, docs, 0)
	})

	t.Run("error - third controller could not be found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		sut := VDR{store: store}
		id789, _ := did.ParseDID("did:nuts:789")
		docA := did.Document{ID: *id123, Controller: []did.DID{*id456}}
		docB := did.Document{ID: *id456, Controller: []did.DID{*id789}}

		gomock.InOrder(
			store.EXPECT().Resolve(*id456, gomock.Any()).Return(&docB, &types.DocumentMetadata{}, nil),
			store.EXPECT().Resolve(*id789, gomock.Any()).Return(nil, nil, types.ErrNotFound),
		)

		docs, err := sut.resolveControllers([]did.Document{docA})
		assert.EqualError(t, err, "unable to resolve controllers: unable to find the did document")
		assert.Len(t, docs, 0)
	})
}
