package didx509

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/minio/sha256-simd"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	resolver2 "github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestManager_Resolve(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain(otherNameValue)
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders["x5c"] = certChain
	metadata.JwtProtectedHeaders["x5t"] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders["x5t#S256"] = sha256Sum(signingCert.Raw)

	rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValue))

	t.Run("test nulls", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain("x5c")
		delete(metadata.JwtProtectedHeaders, "x5c")
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("x509 rootCert chain is missing").Error())
		metadata.JwtProtectedHeaders["x5c"] = chain

	})
	t.Run("test x5c cast issue", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain("x5c")
		metadata.JwtProtectedHeaders["x5c"] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("x509 rootCert chain is missing").Error())
		metadata.JwtProtectedHeaders["x5c"] = chain

	})
	t.Run("happy flow", func(t *testing.T) {
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow 2", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, "x5t#S256")
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders["x5t#S256"] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow 2", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, "x5t")
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders["x5t"] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken chain", func(t *testing.T) {
		expectedErr := errors.New("broken chain")
		validator.EXPECT().Validate(gomock.Any()).Return(expectedErr)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), expectedErr.Error())
	})
	t.Run("wrong otherName value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrWrongSanOtherName.Error())
	})
	t.Run("wrong hash type value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "kaas", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("unsupported hash algorithm: kaas").Error())
	})
	t.Run("wrong hash value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", "kaas", "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("cannot find a certificate with alg: sha256 hash: kaas").Error())
	})
	t.Run("wrong DID type", func(t *testing.T) {
		rootDID := did.MustParseDID("did:kaas:gouda.nl:jonge")
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), fmt.Errorf("unsupported DID method: %s", "kaas").Error())
	})
	t.Run("wrong x509 did version", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:1:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrDidVersion.Error())
	})
	t.Run("missing x509 did version", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:%s:%s::san:otherName:%s", "sha256Sum", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrDidMalformed.Error())
	})
}

func sha1Sum(raw []byte) string {
	sum := sha1.Sum(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sha256Sum(bytes []byte) string {
	rootHash := sha256.Sum256(bytes)
	rootHashStr := base64.RawURLEncoding.EncodeToString(rootHash[:])
	return rootHashStr
}
