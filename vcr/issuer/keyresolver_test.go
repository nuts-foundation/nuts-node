package issuer

import (
	"errors"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_vdrKeyResolver_ResolveAssertionKey(t *testing.T) {
	issuerDID, _ := did.ParseDID("did:nuts:123")
	methodID := *issuerDID
	methodID.Fragment = "abc"
	newMethod, err := did.NewVerificationMethod(methodID, ssi.JsonWebKey2020, *issuerDID, crypto.NewTestKey(issuerDID.String()+"abc").Public())
	if !assert.NoError(t, err) {
		return
	}
	docWithAssertionKey := &did.Document{}
	docWithAssertionKey.AddAssertionMethod(newMethod)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockDockResolver := types.NewMockDocResolver(ctrl)
		mockDockResolver.EXPECT().Resolve(*issuerDID, nil).Return(docWithAssertionKey, &types.DocumentMetadata{}, nil)
		mockKeyResolver := crypto.NewMockKeyResolver(ctrl)
		mockKeyResolver.EXPECT().Resolve(methodID.String()).Return(crypto.NewTestKey(methodID.String()), nil)

		sut := vdrKeyResolver{
			docResolver: mockDockResolver,
			keyResolver: mockKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(*issuerDID)

		assert.NotNil(t, key)
		assert.Implements(t, (*crypto.Key)(nil), key)
		assert.NoError(t, err)
	})

	t.Run("document for issuer not found in vdr", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockDockResolver := types.NewMockDocResolver(ctrl)
		mockDockResolver.EXPECT().Resolve(*issuerDID, nil).Return(nil, nil, errors.New("not found"))
		mockKeyResolver := crypto.NewMockKeyResolver(ctrl)

		sut := vdrKeyResolver{
			docResolver: mockDockResolver,
			keyResolver: mockKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(*issuerDID)

		assert.Nil(t, key)
		assert.EqualError(t, err, "failed to resolve assertionKey: could not resolve did document is vdr: not found")
	})

	t.Run("key not found in crypto", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockDockResolver := types.NewMockDocResolver(ctrl)
		mockDockResolver.EXPECT().Resolve(*issuerDID, nil).Return(docWithAssertionKey, &types.DocumentMetadata{}, nil)
		mockKeyResolver := crypto.NewMockKeyResolver(ctrl)
		mockKeyResolver.EXPECT().Resolve(methodID.String()).Return(nil, errors.New("not found"))

		sut := vdrKeyResolver{
			docResolver: mockDockResolver,
			keyResolver: mockKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(*issuerDID)
		assert.Nil(t, key)
		assert.EqualError(t, err, "failed to resolve assertionKey: could not resolve key from keyStore: not found")
	})

	t.Run("did document has no assertionKey", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockDockResolver := types.NewMockDocResolver(ctrl)
		mockDockResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &types.DocumentMetadata{}, nil)
		mockKeyResolver := crypto.NewMockKeyResolver(ctrl)

		sut := vdrKeyResolver{
			docResolver: mockDockResolver,
			keyResolver: mockKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(*issuerDID)
		assert.Nil(t, key)
		assert.EqualError(t, err, "invalid issuer: key not found in DID document")
	})

}
