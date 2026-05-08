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
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/minio/sha256-simd"
	"github.com/nuts-foundation/go-did/did"
	testpki "github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_Resolve(t *testing.T) {
	didResolver := NewResolver()
	metadata := resolver.ResolveMetadata{}

	otherNameValue := "A_BIG_STRING"
	otherNameValueSecondary := "A_SECOND_STRING"
	certs, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "", nil)
	require.NoError(t, err)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)

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
	t.Run("happy flow with alternative hash alg sha512", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha512", sha512Sum(rootCertificate.Raw), otherNameValue))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
	})
	t.Run("happy flow with alternative hash alg sha384", func(t *testing.T) {
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::san:otherName:%s", "sha384", sha384Sum(rootCertificate.Raw), otherNameValue))
		resolve, documentMetadata, err := didResolver.Resolve(rootDID, &metadata)
		require.NoError(t, err)
		assert.NotNil(t, resolve)
		assert.NotNil(t, documentMetadata)
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
	t.Run("invalid signature of root certificate", func(t *testing.T) {
		craftedCerts, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "", nil)
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

		_, _, err = didResolver.Resolve(rootDID, &metadata)
		require.ErrorContains(t, err, "did:509 certificate chain validation failed: x509: certificate signed by unknown authority")
	})
	t.Run("did:x509 from UZI card", func(t *testing.T) {
		certsBase64 := []string{
			"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",
		}
		chain := new(cert.Chain)
		for _, certB64 := range certsBase64 {
			err := chain.Add([]byte(certB64))
			require.NoError(t, err)
		}
		uziDID := did.MustParseDID("did:x509:0:sha256:KY3NR_y2OphPtJev5NxWhxJ7A-4bNta8OTRnalCbIv4::subject:O:T%C3%A9st%20Zorginstelling%2001::san:otherName:2.16.528.1.1007.99.217-1-900030757-Z-90000380-01.015-00000000")
		metadata := resolver.ResolveMetadata{}
		metadata.JwtProtectedHeaders = make(map[string]interface{})
		metadata.JwtProtectedHeaders[X509CertChainHeader] = chain
		_, _, err = didResolver.Resolve(uziDID, &metadata)
		require.NoError(t, err)

	})
	t.Run("x5c contains extra certs", func(t *testing.T) {
		metadata := resolver.ResolveMetadata{
			JwtProtectedHeaders: map[string]interface{}{
				X509CertChainHeader: testpki.CertsToChain(append(certs, certs[0])),
			},
		}
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s", "sha256", sha256Sum(rootCertificate.Raw)))
		_, _, err := didResolver.Resolve(rootDID, &metadata)

		require.EqualError(t, err, "did:x509 x5c header contains more certificates than the validated certificate chain")
	})
	t.Run("no key usage in signing certificate", func(t *testing.T) {
		keyUsage := x509.KeyUsage(0)
		certs, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "", &keyUsage)
		require.NoError(t, err)

		metadata := resolver.ResolveMetadata{
			JwtProtectedHeaders: map[string]interface{}{
				X509CertChainHeader: testpki.CertsToChain(certs),
			},
		}
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s", "sha256", sha256Sum(rootCertFromCerts(certs).Raw)))
		didDocument, _, err := didResolver.Resolve(rootDID, &metadata)

		require.NoError(t, err)
		assert.Len(t, didDocument.AssertionMethod, 1)
		assert.Len(t, didDocument.KeyAgreement, 1)
	})
	t.Run("key usage in signing certificate, but neither digitalSignature or keyAgreement", func(t *testing.T) {
		keyUsage := x509.KeyUsageCertSign
		certs, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "", &keyUsage)
		require.NoError(t, err)

		metadata := resolver.ResolveMetadata{
			JwtProtectedHeaders: map[string]interface{}{
				X509CertChainHeader: testpki.CertsToChain(certs),
			},
		}
		rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s", "sha256", sha256Sum(rootCertFromCerts(certs).Raw)))
		_, _, err = didResolver.Resolve(rootDID, &metadata)

		require.EqualError(t, err, "did:x509 certificate must have either digitalSignature or keyAgreement set as key usage bits")
	})
	t.Run("invalid issuer signature of leaf certificate", func(t *testing.T) {
		craftedCerts, _, err := testpki.BuildCertChain([]string{otherNameValue, otherNameValueSecondary}, "", nil)
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

	certs, _, err := testpki.BuildCertChain([]string{}, "", nil)
	require.NoError(t, err)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)

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
	certs, _, err := testpki.BuildCertChain([]string{otherNameValue}, "", nil)
	require.NoError(t, err)
	rootCertificate := rootCertFromCerts(certs)
	metadata.JwtProtectedHeaders = make(map[string]interface{})
	metadata.JwtProtectedHeaders[X509CertChainHeader] = testpki.CertsToChain(certs)

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
