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
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/minio/sha256-simd"
	"github.com/nuts-foundation/go-did/did"
	testpki "github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestManager_Resolve_OtherName(t *testing.T) {
	didResolver := NewResolver()
	metadata := resolver.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	otherNameValueSecondary := "A_SECOND_STRING"
	certs, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "")
	require.NoError(t, err)
	signingCert := leafCertFromCerts(certs)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(leafCertFromCerts(certs).Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(leafCertFromCerts(certs).Raw)

	rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertFromCerts(certs).Raw), otherNameValue))

	t.Run("test nulls", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain(X509CertChainHeader)
		delete(metadata.JwtProtectedHeaders, X509CertChainHeader)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, ErrX509ChainMissing.Error(), err.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("test x5c cast issue", func(t *testing.T) {
		chain, _ := metadata.GetProtectedHeaderChain(X509CertChainHeader)
		metadata.JwtProtectedHeaders[X509CertChainHeader] = "GARBAGE"
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, ErrX509ChainMissing.Error(), err.Error())
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain

	})
	t.Run("happy flow, policy depth of 0", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s", "sha256", sha256Sum(rootCertificate.Raw)))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.NotNil(t, resolve)
		require.NoError(t, err)
		assert.NotNil(t, documentMetadata)
		// Check that the DID url is did#0
		didUrl, err := did.ParseDIDURL(rootDID.String() + "#0")
		assert.NotNil(t, resolve.VerificationMethod.FindByID(*didUrl))
	})
	t.Run("happy flow, policy depth of 1 and primary value", func(t *testing.T) {
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

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

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

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

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

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

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

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

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)

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
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow with only x5t#S256 header", func(t *testing.T) {
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow without x5t or x5t#S256 header", func(t *testing.T) {
		expectedErr := ErrNoCertsInHeaders
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintS256Header)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, expectedErr, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha512", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha512", sha512Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow with alternative hash alg sha384", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha384", sha384Sum(rootCertificate.Raw), otherNameValue))
		delete(metadata.JwtProtectedHeaders, X509CertThumbprintHeader)
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("happy flow with ca-fingerprint pointing at intermediate CA", func(t *testing.T) {
		subjectDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(certs[2].Raw), otherNameValue))

		resolve, documentMetadata, err := didResolver.Resolve(subjectDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("ca-fingerprint pointing at leaf certificate, which is not allowed", func(t *testing.T) {
		subjectDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(leafCertFromCerts(certs).Raw), otherNameValue))

		_, _, err := didResolver.Resolve(subjectDID, &metadata)
		require.EqualError(t, err, "did:x509 ca-fingerprint refers to leaf certificate, must be either root or intermediate CA certificate")
	})
	t.Run("broken thumbprint at x5t", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = "GARBAGE"
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint at x5t#S256", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = "GARBAGE"
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(rootCertificate.Raw)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMatchingHeaderCredentials)
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(signingCert.Raw)
	})
	t.Run("broken thumbprint with wrong hash at x5t#S256", func(t *testing.T) {
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(rootCertificate.Raw)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMatchingHeaderCredentials)
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)
	})
	t.Run("invalid signature of root certificate", func(t *testing.T) {
		craftedCerts, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "")
		require.NoError(t, err)

		craftedCertChain := new(cert.Chain)
		// Do not add last cert, since it's the root CA cert, which should be the crafted certificate
		for i := 0; i < len(certs)-1; i++ {
			require.NoError(t, craftedCertChain.Add([]byte(base64.StdEncoding.EncodeToString(certs[i].Raw))))
		}
		require.NoError(t, craftedCertChain.Add([]byte(base64.StdEncoding.EncodeToString(rootCertFromCerts(craftedCerts).Raw))))

		// recreate DID with crafted root cert for ca-fingerprint
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertFromCerts(craftedCerts).Raw), otherNameValue))

		metadata := resolver.ResolveMetadata{}
		metadata.JwtProtectedHeaders = make(map[string]interface{})
		metadata.JwtProtectedHeaders[X509CertChainHeader] = craftedCertChain
		metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(signingCert.Raw)

		_, _, err = didResolver.Resolve(rootDID, &metadata)
		require.ErrorContains(t, err, "did:509 certificate chain validation failed: x509: certificate signed by unknown authority")
	})
	t.Run("invalid issuer signature of leaf certificate", func(t *testing.T) {
		craftedCerts, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "")
		require.NoError(t, err)

		craftedCertChain := new(cert.Chain)
		// Do not add first cert, since it's the leaf, which should be the crafted certificate
		require.NoError(t, craftedCertChain.Add([]byte(base64.StdEncoding.EncodeToString(leafCertFromCerts(craftedCerts).Raw))))
		for i := 1; i < len(certs); i++ {
			require.NoError(t, craftedCertChain.Add([]byte(base64.StdEncoding.EncodeToString(certs[i].Raw))))
		}

		metadata := resolver.ResolveMetadata{}
		metadata.JwtProtectedHeaders = make(map[string]interface{})
		metadata.JwtProtectedHeaders[X509CertChainHeader] = craftedCertChain
		metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(leafCertFromCerts(craftedCerts).Raw)

		_, _, err = didResolver.Resolve(rootDID, &metadata)
		require.ErrorContains(t, err, "did:509 certificate chain validation failed: x509: certificate signed by unknown authority")
	})
	t.Run("wrong otherName value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute otherName does not match the query")
	})
	t.Run("wrong hash type value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "test", sha256Sum(rootCertificate.Raw), otherNameValue))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrUnsupportedHashAlgorithm, err)
	})
	t.Run("wrong hash value", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha256", "test", otherNameValue))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, ErrCertificateNotfound, err)
	})
	t.Run("wrong DID type", func(t *testing.T) {
		expectedErr := fmt.Sprintf("unsupported DID method: %s", "test")
		rootDID := did.MustParseDID("did:test:example.com:testing")
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, expectedErr)
	})
	t.Run("wrong x509 did version", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:1:%s:%s::san:otherName:%s", "sha256", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidVersion)
	})
	t.Run("missing x509 hash unk", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:%s:%s::san:otherName:%s", "unk", sha256Sum(rootCertificate.Raw), "ANOTHER_BIG_STRING"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidMalformed)
	})
}

func TestManager_Resolve_San_Generic(t *testing.T) {
	didResolver := NewResolver()
	metadata := resolver.ResolveMetadata{}

	certs, _, err := testpki.BuildCertChain([]string{}, "")
	require.NoError(t, err)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(leafCertFromCerts(certs).Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(leafCertFromCerts(certs).Raw)

	t.Run("unk san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:unknown:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "unknown policy key: unknown for policy: san")
	})
	t.Run("impartial san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("broken san attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.uva.nl", "www.uva%2.nl", 1)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "invalid URL escape \"%2.\"")
	})
	t.Run("happy SAN DNS www.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN DNS", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:dns:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.uva.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute dns does not match the query")
	})
	t.Run("happy SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "192.1.2.3"))

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN ip", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:ip:%s", "sha256", sha256Sum(rootCertificate.Raw), "10.0.0.1"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute ip does not match the query")
	})
	t.Run("happy SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "info%40example.com"))

		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error SAN email", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:email:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad%40example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "the SAN attribute email does not match the query")
	})
}

func TestManager_Resolve_Subject(t *testing.T) {
	didResolver := NewResolver()
	metadata := resolver.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	certs, _, err := testpki.BuildCertChain([]string{otherNameValue}, "")
	require.NoError(t, err)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)
	metadata.JwtProtectedHeaders[X509CertThumbprintHeader] = sha1Sum(leafCertFromCerts(certs).Raw)
	metadata.JwtProtectedHeaders[X509CertThumbprintS256Header] = sha256Sum(leafCertFromCerts(certs).Raw)

	t.Run("unknown policy", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::unknown:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnkPolicyType)

	})
	t.Run("unknown policy key", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:UNK:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "unknown policy key: UNK for policy: subject")

	})
	t.Run("broken subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		rootDID.ID = strings.Replace(rootDID.ID, "www.nuts.nl", "www.nuts%2.nl", 1)
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "invalid URL escape \"%2.\"", err.Error())

	})
	t.Run("impartial subject attribute", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.nuts.nl"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)

	})
	t.Run("happy flow CN www.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "www.example.com"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow CN bad.example.com", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "bad.example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "query does not match the subject : CN", err.Error())
	})
	t.Run("happy flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow O and CN", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow O and CN and OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com", "The%20A-Team"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow O and CN broken policy", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CV:%s", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "unknown policy key: CV for policy: subject", err.Error())
	})
	t.Run("error flow O and CN broken policy: extra :", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s:", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("error flow O and CN broken policy, extra :: ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s::", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDidPolicyMalformed)
	})
	t.Run("error flow O and CN broken policy, extra : and garbage ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s::subject:CN:%s:test:", "sha256", sha256Sum(rootCertificate.Raw), "NUTS%20Foundation", "www.example.com"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.Equal(t, "unknown policy key: test for policy: subject", err.Error())
	})
	t.Run("error flow O", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:O:%s", "sha256", sha256Sum(rootCertificate.Raw), "UNKNOW%20NUTS%20Foundation"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : O")
	})
	t.Run("happy flow L Amsterdam", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdam"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow L Den Haag", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20Hague"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow L", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:L:%s", "sha256", sha256Sum(rootCertificate.Raw), "Rotterdam"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : L")
	})
	t.Run("happy flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "NL"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow C", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:%s", "sha256", sha256Sum(rootCertificate.Raw), "BE"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : C")
	})
	t.Run("happy flow ST", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Holland"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow ST ", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:ST:%s", "sha256", sha256Sum(rootCertificate.Raw), "Noord-Brabant"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : ST")
	})
	t.Run("happy flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Amsterdamseweg%20100"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow STREET", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:STREET:%s", "sha256", sha256Sum(rootCertificate.Raw), "Haarlemsetraatweg%2099"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : STREET")
	})

	t.Run("happy flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "32121323"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow serialNumber", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:serialNumber:%s", "sha256", sha256Sum(rootCertificate.Raw), "1"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
		require.Error(t, err)
		assert.EqualError(t, err, "query does not match the subject : serialNumber")
	})
	t.Run("happy flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20A-Team"))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("error flow OU", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:OU:%s", "sha256", sha256Sum(rootCertificate.Raw), "The%20B-Team"))
		_, _, err := didResolver.Resolve(rootDID, &metadata)
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
