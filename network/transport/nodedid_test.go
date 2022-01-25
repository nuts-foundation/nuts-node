package transport

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_AutoNodeDIDResolver(t *testing.T) {
	// Local vendor
	didLocal, _ := did.ParseDID("did:nuts:local")
	key0ID := *didLocal
	key0ID.Fragment = "key-0"
	key1ID := *didLocal
	key1ID.Fragment = "key-1"

	// Other vendor
	didOther, _ := did.ParseDID("did:nuts:other")
	keyOther := *didOther
	keyOther.Fragment = "key-1"

	didDocuments := []did.Document{
		// Other
		{
			ID: *didOther,
			CapabilityInvocation: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: keyOther}},
			},
		},
		// Local
		{
			ID: *didLocal,
			CapabilityInvocation: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: key0ID}},
				{VerificationMethod: &did.VerificationMethod{ID: key1ID}},
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List().Return([]string{key0ID.String(), key1ID.String()})
		docFinder.EXPECT().Find(doc.IsActive(), gomock.Any(), doc.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)
		resolver := NewAutoNodeDIDResolver(keyResolver, docFinder)

		actual, err := resolver.Resolve()

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *didLocal, actual)

		// Call again, mocks should not be triggered again
		actual, err = resolver.Resolve()
		assert.NoError(t, err)
		assert.Equal(t, *didLocal, actual)
	})
	t.Run("no private keys in keystore", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List().Return([]string{})
		docFinder.EXPECT().Find(doc.IsActive(), gomock.Any(), doc.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)
		resolver := NewAutoNodeDIDResolver(keyResolver, docFinder)

		actual, err := resolver.Resolve()

		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
	t.Run("no DID documents match", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List().Return([]string{"non-matching-KID"})
		docFinder.EXPECT().Find(doc.IsActive(), gomock.Any(), doc.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)
		resolver := NewAutoNodeDIDResolver(keyResolver, docFinder)

		actual, err := resolver.Resolve()
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}
