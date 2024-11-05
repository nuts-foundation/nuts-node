/*
 * Copyright (C) 2024 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
	"strings"
	"testing"
)

func TestManager_Resolve_OtherName(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	otherNameValueSecondary := "A_SECOND_STRING"
	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain([]string{otherNameValue, otherNameValueSecondary})
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
		assert.Equal(t, ErrX509ChainMissing.Error(), err.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("test x5c cast issue", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain(X509CertChainHeader)
		metadata.JwtProtectedHeaders[X509CertChainHeader] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, ErrX509ChainMissing.Error(), err.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("happy flow, policy depth of 0", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s", "sha256", sha256Sum(rootCertificate.Raw)))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 1 and primary value", func(t *testing.T) {
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 1 and secondary value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValueSecondary))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 2 of type OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValue, "The%20A-Team"))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 2, primary and secondary", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValue, otherNameValueSecondary))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 2, secondary and primary", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), otherNameValue, otherNameValueSecondary))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow with only x5t header", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintS256Header)
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow with only x5t#S256 header", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow without x5t or x5t#S256 header", func(t *testing.T) {
		expectedErr := ErrNoCertsInHeaders
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintS256Header)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, expectedErr, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha512", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha512", sha512Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha384", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha384", sha384Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint at x5t", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint at x5t#S256", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = "GARBAGE"
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(rootCertificate.Raw)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMatchingHeaderCredentials)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t#S256", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(rootCertificate.Raw)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMatchingHeaderCredentials)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("broken chain", func(t *testing.T) {
		expectedErr := errors.New("broken chain")
		validator.EXPECT().ValidateStrict(gomock.Any()).Return(expectedErr)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, expectedErr)
	})
	t.Run("wrong otherName value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute otherName does not match the query")
	})
	t.Run("wrong hash type value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "test", sha256Sum(rootCertificate.Raw), otherNameValue))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrUnsupportedHashAlgorithm, err)
	})
	t.Run("wrong hash value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", "test", otherNameValue))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
	})
	t.Run("wrong DID type", func(t *testing.T) {
		expectedErr := fmt.Sprintf("unsupported DID method: %s", "test")
		rootDID := did.MustParseDID("did:test:example.com:testing")
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, expectedErr)
	})
	t.Run("wrong x509 did version", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:1:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidVersion)
	})
	t.Run("missing x509 hash unk", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:%s:%s::san:otherName:%s", "unk", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidMalformed)
	})
}

func TestManager_Resolve_San_Generic(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain([]string{})
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = certChain
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

	t.Run("unk san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:unknown:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "unknown policy key: unknown for policy: san")
	})
	t.Run("impartial san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("broken san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.uva.nl", "www.uva%2.nl", 1)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "invalid URL escape \"%2.\"")
	})
	t.Run("happy SAN DNS www.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN DNS", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute dns does not match the query")
	})
	t.Run("happy SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "192.1.2.3"))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "10.0.0.1"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute ip does not match the query")
	})
	t.Run("happy SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "info%40example.com"))

		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad%40example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute email does not match the query")
	})
}

func TestManager_Resolve_Subject(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := pki.NewMockValidator(ctrl)
	resolver := NewResolver(validator)
	metadata := resolver2.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	_, certChain, rootCertificate, _, signingCert, err := BuildCertChain([]string{otherNameValue})
	require.NoError(t, err)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = certChain
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

	t.Run("unknown policy", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::unknown:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnkPolicyType)

	})
	t.Run("unknown policy key", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:UNK:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "unknown policy key: UNK for policy: subject")

	})
	t.Run("broken subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.nuts.nl", "www.nuts%2.nl", 1)
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "invalid URL escape \"%2.\"", err.Error())

	})
	t.Run("impartial subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)

	})
	t.Run("happy flow CN www.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow CN bad.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "query does not match the subject : CN", err.Error())
	})
	t.Run("happy flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow O and CN", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow O and CN and OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com", "The%20A-Team"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow O and CN broken policy", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CV:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "unknown policy key: CV for policy: subject", err.Error())
	})
	t.Run("error flow O and CN broken policy: extra :", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s:", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("error flow O and CN broken policy, extra :: ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s::", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("error flow O and CN broken policy, extra : and garbage ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s:test:", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "unknown policy key: test for policy: subject", err.Error())
	})
	t.Run("error flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "UNKNOW%20NUTS%20Foundation"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : O")
	})
	t.Run("happy flow L Amsterdam", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdam"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow L Den Haag", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20Hague"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow L", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Rotterdam"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : L")
	})
	t.Run("happy flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "NL"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "BE"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : C")
	})
	t.Run("happy flow ST", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Holland"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow ST ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Brabant"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : ST")
	})
	t.Run("happy flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdamseweg%20100"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Haarlemsetraatweg%2099"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : STREET")
	})

	t.Run("happy flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "32121323"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "1"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : serialNumber")
	})
	t.Run("happy flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20A-Team"))
		validator.EXPECT().ValidateStrict(gomock.Any())
		resolve, documentMetadata, err := resolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20B-Team"))
		_, _, err := resolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : OU")
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
	rootHash := sha512.Sum384(bytes)
	rootHashStr := base64.RawURLEncoding.EncodeToString(rootHash[:])
	return rootHashStr
}
