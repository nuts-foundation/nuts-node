package services

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

var holder = *vdr.RandomDID

func TestResolveEndpointURL(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected, _ := url.Parse("http://nuts.nl")
		expectedURI := did.URI{URL: *expected}
		s := did.Service{Type: "oauth", ServiceEndpoint: expectedURI.String()}
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&did.Document{Service: []did.Service{s}}, nil, nil)
		_, endpointURL, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.NoError(t, err)
		assert.Equal(t, expectedURI.String(), endpointURL)
	})
	t.Run("unable to resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		_, _, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.Error(t, err)
	})
	t.Run("no services match", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&did.Document{}, nil, nil)
		_, _, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.EqualError(t, err, "endpoint not found (did=did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW, type=oauth)")
	})
	t.Run("multiple services match", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected, _ := url.Parse("http://nuts.nl")
		expectedURI := did.URI{URL: *expected}
		s := did.Service{Type: "oauth", ServiceEndpoint: expectedURI.String()}
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&did.Document{Service: []did.Service{s, s}}, nil, nil)
		_, _, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.EqualError(t, err, "multiple endpoints found (did=did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW, type=oauth)")
	})
	t.Run("serviceEndpoint is not a single string", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected, _ := url.Parse("http://nuts.nl")
		expectedURI := did.URI{URL: *expected}
		s := did.Service{Type: "oauth", ServiceEndpoint: []string{expectedURI.String(), expectedURI.String()}}
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&did.Document{Service: []did.Service{s}}, nil, nil)
		_, _, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.EqualError(t, err, "unable to unmarshal single URL from service (id=): json: cannot unmarshal array into Go value of type string")
	})
}

func TestResolveSigningKey(t *testing.T) {
	privateKey := test.GenerateECKey()
	keyID := holder
	keyID.Fragment = "key-1"
	vm, _ := did.NewVerificationMethod(keyID, did.JsonWebKey2020, holder, privateKey.Public())
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		doc := did.Document{}
		doc.AddAssertionMethod(vm)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&doc, nil, nil)
		actual, err := ResolveSigningKey(resolver, keyID.String(), nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, privateKey.Public(), actual)
	})
	t.Run("unable to resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		_, err := ResolveSigningKey(resolver, keyID.String(), nil)
		assert.Error(t, err)
	})
	t.Run("signing key not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		doc := did.Document{}
		doc.AddAuthenticationMethod(vm)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&doc, nil, nil)
		_, err := ResolveSigningKey(resolver, keyID.String(), nil)
		assert.EqualError(t, err, "signing key not found (id=did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#key-1)")
	})
	t.Run("invalid key ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		resolver := types.NewMockDocResolver(ctrl)
		_, err := ResolveSigningKey(resolver, "asdasdsa", nil)
		assert.Error(t, err)
	})
}

func TestResolveSigningKeyID(t *testing.T) {
	privateKey := test.GenerateECKey()
	keyID := holder
	keyID.Fragment = "key-1"
	vm, _ := did.NewVerificationMethod(keyID, did.JsonWebKey2020, holder, privateKey.Public())
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		doc := did.Document{}
		doc.AddAssertionMethod(vm)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&doc, nil, nil)
		actual, err := ResolveSigningKeyID(resolver, holder, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, keyID.String(), actual)
	})
	t.Run("unable to resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		_, err := ResolveSigningKeyID(resolver, holder, nil)
		assert.Error(t, err)
	})
	t.Run("signing key not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		doc := did.Document{}
		doc.AddAuthenticationMethod(vm)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&doc, nil, nil)
		_, err := ResolveSigningKeyID(resolver, holder, nil)
		assert.EqualError(t, err, "DID Document has no assertionMethod keys (did=did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW)")
	})
}
