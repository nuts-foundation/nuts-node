package vdr

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_cachingDocumentOwner_IsOwner(t *testing.T) {
	id := did.MustParseDID("did:nuts:example.com")
	t.Run("owned, cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := types.NewMockDocumentOwner(ctrl)
		underlying.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)

		documentOwner := newCachingDocumentOwner(underlying)
		result, err := documentOwner.IsOwner(context.Background(), id)
		assert.NoError(t, err)
		assert.True(t, result)
		result, err = documentOwner.IsOwner(context.Background(), id)
		assert.True(t, result)
		assert.NoError(t, err)
	})
	t.Run("not owned, cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := types.NewMockDocumentOwner(ctrl)
		underlying.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)

		documentOwner := newCachingDocumentOwner(underlying)
		result, err := documentOwner.IsOwner(context.Background(), id)
		assert.False(t, result)
		assert.NoError(t, err)
		result, err = documentOwner.IsOwner(context.Background(), id)
		assert.False(t, result)
		assert.NoError(t, err)
	})
}

func Test_privateKeyDocumentOwner_IsOwner(t *testing.T) {
	keyList := []string{
		"did:nuts:example.com#key-1",
		"did:nuts:example.com",
		"",
		"not a DID",
		"did:nuts:another-did.com#key-2",
		"did:nuts:example.com#key-2",
	}
	t.Run("owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().List(gomock.Any()).Return(keyList)
		documentOwner := privateKeyDocumentOwner{keyResolver: keyResolver}

		result, err := documentOwner.IsOwner(context.Background(), did.MustParseDID("did:nuts:example.com"))
		assert.True(t, result)
		assert.NoError(t, err)
	})
	t.Run("not owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().List(gomock.Any()).Return(keyList)
		documentOwner := privateKeyDocumentOwner{keyResolver: keyResolver}

		result, err := documentOwner.IsOwner(context.Background(), did.MustParseDID("did:nuts:voorbeeld.nl"))
		assert.False(t, result)
		assert.NoError(t, err)
	})
}
