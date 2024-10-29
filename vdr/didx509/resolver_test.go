package didx509

import (
	"crypto/sha1"
	"crypto/sha512"
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
	"golang.org/x/crypto/sha3"
	"strings"
	"testing"
)

func TestManager_Resolve_OtherName(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain(otherNameValue)
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = certChain
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

	rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValue))

	t.Run("test nulls", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain(X509CertChainHeader)
		delete(metadata.JwtProtectedHeaders, X509CertChainHeader)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrX509ChainMissing.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("test x5c cast issue", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain(X509CertChainHeader)
		metadata.JwtProtectedHeaders[X509CertChainHeader] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrX509ChainMissing.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("happy flow", func(t *testing.T) {
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow with only x5t header", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintS256Header)
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow with only x5t#S256 header", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha512", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha512", sha512Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha384", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha384", sha384Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint at x5t", func(t *testing.T) {
		expectedErr := errors.New("cannot find a certificate with alg: sha1 hash: GARBAGE")
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), expectedErr.Error())
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint at x5t#S256", func(t *testing.T) {
		expectedErr := errors.New("cannot find a certificate with alg: sha256 hash: GARBAGE")
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), expectedErr.Error())
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t", func(t *testing.T) {
		expectedErr := errors.New("x5t#S256 header does not match the certificate from the x5t headers")
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(rootCertificate.Raw)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), expectedErr.Error())
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t#S256", func(t *testing.T) {
		expectedErr := errors.New("x5t#S256 header does not match the certificate from the x5t headers")
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(rootCertificate.Raw)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), expectedErr.Error())
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
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
		assert.Equal(t, err.Error(), "the SAN attribute otherName does not match the query")
	})
	t.Run("wrong hash type value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "test", sha256Sum(rootCertificate.Raw), otherNameValue))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("unsupported hash algorithm: test").Error())
	})
	t.Run("wrong hash value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", "test", otherNameValue))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), errors.New("cannot find a certificate with alg: sha256 hash: test").Error())
	})
	t.Run("wrong DID type", func(t *testing.T) {
		rootDID := did.MustParseDID("did:test:example.com:testing")
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), fmt.Errorf("unsupported DID method: %s", "test").Error())
	})
	t.Run("wrong x509 did version", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:1:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrDidVersion.Error())
	})
	t.Run("missing x509 hash unk", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:%s:%s::san:otherName:%s", "unk", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrDidMalformed.Error())
	})
}

func TestManager_Resolve_San_Generic(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain("")
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = certChain
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

	t.Run("unk san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:unknown:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "unknown policy key: unknown for policy: san")
	})
	t.Run("impartial san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrDidPolicyMalformed.Error())
	})
	t.Run("broken san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.uva.nl", "www.uva%2.nl", 1)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "invalid URL escape \"%2.\"")
	})
	t.Run("happy SAN DNS www.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))

		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN DNS", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "the SAN attribute dns does not match the query")
	})
	t.Run("happy SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "192.1.2.3"))

		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "10.0.0.1"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "the SAN attribute ip does not match the query")
	})
	t.Run("happy SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "info%40example.com"))

		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad%40example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "the SAN attribute email does not match the query")
	})
}

func TestManager_Resolve_Subject(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain(otherNameValue)
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = certChain
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

	t.Run("unknown policy", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::unknown:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), ErrUnkPolicyType.Error())

	})
	t.Run("unknown policy key", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:UNK:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "unknown policy key: UNK for policy: subject")

	})
	t.Run("broken subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.nuts.nl", "www.nuts%2.nl", 1)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "invalid URL escape \"%2.\"")

	})
	t.Run("impartial subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "did:x509 policy is malformed")

	})
	t.Run("happy flow CN www.example.com\"", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow CN bad.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : CN")
	})
	t.Run("happy flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "UNKNOW%20NUTS%20Foundation"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : O")
	})
	t.Run("happy flow L Amsterdam", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdam"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow L Den Haag", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20Hague"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow L", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Rotterdam"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : L")
	})
	t.Run("happy flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "NL"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "BE"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : C")
	})
	t.Run("happy flow ST", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Holland"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow ST ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Brabant"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : ST")
	})
	t.Run("happy flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdamseweg%20100"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Haarlemsetraatweg%2099"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : STREET")
	})

	t.Run("happy flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "32121323"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "1"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : serialNumber")
	})
	t.Run("happy flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20A-Team"))
		validator.EXPECT().Validate(gomock.Any()).Return(nil)
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20B-Team"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, err.Error(), "query does not match the subject : OU")
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
func sha512Sum(bytes []byte) string {
	rootHash := sha512.Sum512(bytes)
	rootHashStr := base64.RawURLEncoding.EncodeToString(rootHash[:])
	return rootHashStr
}
func sha384Sum(bytes []byte) string {
	rootHash := sha3.Sum384(bytes)
	rootHashStr := base64.RawURLEncoding.EncodeToString(rootHash[:])
	return rootHashStr
}
