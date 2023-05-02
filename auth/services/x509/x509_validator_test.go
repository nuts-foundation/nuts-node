/*
 * Copyright (C) 2021 Nuts community
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

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/pki"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewJwtX509Validator(t *testing.T) {
	rootCert, rootCertKey, err := createTestRootCert()
	require.NoError(t, err)

	intermediateCert, intermediateCerKey, err := createIntermediateCert(rootCert, rootCertKey)
	require.NoError(t, err)

	leafCert, _, err := createLeafCert(intermediateCert, intermediateCerKey)
	require.NoError(t, err)

	t.Run("validator with only a root", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, nil, nil, nil)
		assert.NotNil(t, validator)

		t.Run("ok - leaf and intermediate in token", func(t *testing.T) {
			leaf, chain, err := validator.verifyCertChain([]*x509.Certificate{leafCert, intermediateCert}, time.Now())
			require.NoError(t, err)
			assert.Equal(t, leafCert, leaf)
			assert.Len(t, chain[0], 3)
		})

		t.Run("nok - intermediate missing from token", func(t *testing.T) {
			leaf, chain, err := validator.verifyCertChain([]*x509.Certificate{leafCert}, time.Now())
			assert.ErrorContains(t, err, "unable to verify certificate chain: x509: certificate signed by unknown authority")
			assert.Nil(t, leaf)
			assert.Nil(t, chain)
		})

		t.Run("nok - complete chain in token, but not part of roots", func(t *testing.T) {
			otherRootCert, _, _ := createTestRootCert()
			validator := NewJwtX509Validator([]*x509.Certificate{otherRootCert}, nil, nil, nil)
			_, _, err := validator.verifyCertChain([]*x509.Certificate{leafCert, intermediateCert, rootCert}, time.Now())
			assert.Error(t, err)
			assert.EqualError(t, err, "unable to verify certificate chain: x509: certificate signed by unknown authority (possibly because of \"crypto/rsa: verification error\" while trying to verify candidate authority certificate \"Nuts Test - Root CA\")")
		})

	})

	t.Run("nok - root is not a root", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{intermediateCert}, nil, nil, nil)
		leaf, chain, err := validator.verifyCertChain([]*x509.Certificate{leafCert}, time.Now())
		assert.Nil(t, leaf)
		assert.Nil(t, chain)
		require.ErrorContains(t, err, "certificate 'CN=Nuts Test - Intermediate CA,O=Nuts,C=NL' is not a root CA")
	})

	t.Run("validator with root and intermediates", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, []*x509.Certificate{intermediateCert}, nil, nil)
		assert.NotNil(t, validator)

		t.Run("ok - valid chain", func(t *testing.T) {
			leaf, chain, err := validator.verifyCertChain([]*x509.Certificate{leafCert}, time.Now())
			require.NoError(t, err)
			assert.Equal(t, leafCert, leaf)
			assert.Len(t, chain[0], 3)
		})

		t.Run("nok - token without leaf cert", func(t *testing.T) {
			leaf, chain, err := validator.verifyCertChain([]*x509.Certificate{}, time.Now())
			assert.ErrorContains(t, err, "JWT x5c field does not contain certificates")
			assert.Nil(t, leaf)
			assert.Nil(t, chain)
		})

	})
	t.Run("nok - validator without roots", func(t *testing.T) {
		validator := NewJwtX509Validator(nil, []*x509.Certificate{rootCert, intermediateCert}, nil, nil)
		_, _, err := validator.verifyCertChain([]*x509.Certificate{leafCert, intermediateCert}, time.Now())
		assert.ErrorContains(t, err, "unable to verify certificate chain: x509: certificate signed by unknown authority")
	})
}

func TestJwtX509Validator_Parse(t *testing.T) {
	validator := NewJwtX509Validator(nil, nil, nil, nil)
	cert, privKey, err := createTestRootCert()
	require.NoError(t, err)
	t.Run("ok - a valid jwt", func(t *testing.T) {
		theJwt := jwt.New()
		headers := jws.NewHeaders()
		err := headers.Set(jws.X509CertChainKey, []string{base64.StdEncoding.EncodeToString(cert.Raw)})
		require.NoError(t, err)
		rawToken, err := jwt.Sign(theJwt, jwa.RS256, privKey, jwt.WithHeaders(headers))
		require.NoError(t, err)
		token, err := validator.Parse(string(rawToken))
		assert.NotNil(t, token)
		assert.NoError(t, err)
	})

	t.Run("nok - empty jwt", func(t *testing.T) {
		token, err := validator.Parse("")
		assert.Nil(t, token)
		require.ErrorContains(t, err, "the jwt should contain out of 3 parts: invalid number of segments")
	})

	t.Run("nok - invalid header", func(t *testing.T) {
		token, err := validator.Parse("header.payload.signature")
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "could not parse jwt headers: invalid character")
	})

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	t.Run("nok - emtpy x5c header field", func(t *testing.T) {
		theJwt := jwt.New()
		signedJwt, err := jwt.Sign(theJwt, jwa.RS256, priv)
		require.NoError(t, err)
		token, err := validator.Parse(string(signedJwt))
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "the jwt x5c field should contain at least 1 certificate")
	})

	t.Run("nok - invalid base64 data in x5c header", func(t *testing.T) {
		theJwt := jwt.New()
		headers := jws.NewHeaders()
		assert.NoError(t, headers.Set(jws.X509CertChainKey, []string{"123"}))
		signedJwt, err := jwt.Sign(theJwt, jwa.RS256, priv, jwt.WithHeaders(headers))
		require.NoError(t, err)
		token, err := validator.Parse(string(signedJwt))
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "could not parse certificates from headers: could not base64 decode certificate: illegal base64 data at input byte 0")

	})
	t.Run("nok - invalid cert in x5c header", func(t *testing.T) {
		theJwt := jwt.New()
		headers := jws.NewHeaders()
		assert.NoError(t, headers.Set(jws.X509CertChainKey, []string{"WvLTlMrX9NpYDQlEIFlnDA=="}))
		signedJwt, err := jwt.Sign(theJwt, jwa.RS256, priv, jwt.WithHeaders(headers))
		require.NoError(t, err)
		token, err := validator.Parse(string(signedJwt))
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "could not parse certificates from headers: could not parse certificate: x509: malformed certificate")
	})

	t.Run("nok - alg header different from actual signing algorithm", func(t *testing.T) {
		t.SkipNow()
		//b64Cert := base64.StdEncoding.EncodeToString(cert.Raw)
		//theJwt := jwt.New()
		//headers := jws.NewHeaders()
		//assert.NoError(t, headers.Set(jws.X509CertChainKey, []string{b64Cert}))
		//// set wrong algorithm
		//headers.Set(jws.AlgorithmKey, jwa.RS256)
		//signer, err := sign.New(jwa.RS512)
		//if !assert.NoError(t, err) {
		//	return
		//}
		//
		//hdrbuf, err := json.Marshal(headers)
		//if !assert.NoError(t, err) {
		//	return
		//}
		//encodedHeader := base64.RawURLEncoding.EncodeToString(hdrbuf)
		//
		//payloadbuf, err := json.Marshal(theJwt)
		//if !assert.NoError(t, err) {
		//	return
		//}
		//encodedPayload := base64.RawURLEncoding.EncodeToString(payloadbuf)
		//dataToSign := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
		//
		//signature, err := signer.Sign([]byte(dataToSign), privKey)
		//if !assert.NoError(t, err) {
		//	return
		//}
		//signedJwt := fmt.Sprintf("%s.%s", dataToSign, base64.RawURLEncoding.EncodeToString(signature))
		//
		//token, err := validator.Parse(string(signedJwt))
		//assert.Nil(t, token)
		//if assert.Error(t, err) {
		//	assert.Equal(t, "could not verify jwt signature: failed to verify message: crypto/rsa: verification error", err.Error())
		//}
	})

}

func TestJwtX509Validator_SubjectAltNameOtherName(t *testing.T) {
	t.Run("ok - parse an UZI signature", func(t *testing.T) {
		// prepare token with leaf cert from uzi card:
		b64EncodedCert := "MIIHczCCBVugAwIBAgIUHPU8qVXKqDeprYHCCWKBi+vJtVYwDQYJKoZIhvcNAQELBQAwajELMAkGA1UEBhMCTkwxDTALBgNVBAoMBENJQkcxFzAVBgNVBGEMDk5UUk5MLTUwMDAwNTM1MTMwMQYDVQQDDCpURVNUIFVaSS1yZWdpc3RlciBNZWRld2Vya2VyIG9wIG5hYW0gQ0EgRzMwHhcNMjAwNzE3MTIzNDE5WhcNMjMwNzE3MTIzNDE5WjCBhTELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF1TDqXN0IFpvcmdpbnN0ZWxsaW5nIDAzMRYwFAYDVQQEDA10ZXN0LTkwMDE3OTQzMQwwCgYDVQQqDANKYW4xEjAQBgNVBAUTCTkwMDAyMTIxOTEaMBgGA1UEAwwRSmFuIHRlc3QtOTAwMTc5NDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChTYhPA7X0S5cVBxGc7GZ/5DvqIesij0aJZvYLqXkFi39NDB4KH38srHltFUf29QwbPRRoJ8BIazENxdu88YD/epJHhf9Hi2LuPhhfgRSqcJzxt3Oa+J0Ouc7gg0Yk+gWMTJByGfRbTPGuyyQE2rNPRmx4h9CKH6b4uYjmDH2Vuya3pmcE+Gl1ne/BrcbtlJjBkgzVL6reSc7OQxon/YnaQjxojBiglaOHnobDIOms9nBFEConS5J4fooUQU87jqLHiGrBM/lMtyZ9EknXFCu6SuQovC6TuyFvsBgOC273FgBZGerly3m1DUw3NTNPmyvRDQtDXBGN/AVEI/4xTgF/AgMBAAGjggLzMIIC7zBRBgNVHREESjBIoEYGA1UFBaA/Fj0yLjE2LjUyOC4xLjEwMDcuOTkuMjE4LTEtOTAwMDIxMjE5LU4tOTAwMDAzODItMDAuMDAwLTAwMDAwMDAwMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUyfAGDpLfNi8IdTi83+5BebJdwF8wgasGCCsGAQUFBwEBBIGeMIGbMGsGCCsGAQUFBzAChl9odHRwOi8vd3d3LnV6aS1yZWdpc3Rlci10ZXN0Lm5sL2NhY2VydHMvMjAxOTA1MDFfdGVzdF91emktcmVnaXN0ZXJfbWVkZXdlcmtlcl9vcF9uYWFtX2NhX2czLmNlcjAsBggrBgEFBQcwAYYgaHR0cDovL29jc3AudXppLXJlZ2lzdGVyLXRlc3QubmwwggEGBgNVHSAEgf4wgfswgfgGCWCEEAGHb2OBVDCB6jA/BggrBgEFBQcCARYzaHR0cHM6Ly9hY2NlcHRhdGllLnpvcmdjc3AubmwvY3BzL3V6aS1yZWdpc3Rlci5odG1sMIGmBggrBgEFBQcCAjCBmQyBlkNlcnRpZmljYWF0IHVpdHNsdWl0ZW5kIGdlYnJ1aWtlbiB0ZW4gYmVob2V2ZSB2YW4gZGUgVEVTVCB2YW4gaGV0IFVaSS1yZWdpc3Rlci4gSGV0IFVaSS1yZWdpc3RlciBpcyBpbiBnZWVuIGdldmFsIGFhbnNwcmFrZWxpamsgdm9vciBldmVudHVlbGUgc2NoYWRlLjAfBgNVHSUEGDAWBggrBgEFBQcDBAYKKwYBBAGCNwoDDDBjBgNVHR8EXDBaMFigVqBUhlJodHRwOi8vd3d3LnV6aS1yZWdpc3Rlci10ZXN0Lm5sL2NkcC90ZXN0X3V6aS1yZWdpc3Rlcl9tZWRld2Vya2VyX29wX25hYW1fY2FfZzMuY3JsMB0GA1UdDgQWBBSY0drXQ0JH6hHv/sz1S+yrjEhSQzAOBgNVHQ8BAf8EBAMCBkAwDQYJKoZIhvcNAQELBQADggIBAF07WZhh6Lyegc22lp20oLy+kgRPwN/S/ISvLFTF4DPAI66FkUJsFRafmua0Zl/BOge5Ivp0s9tEjhpZ16X4eYBmj8MU0xAN348/OjAmIFSGIuwi1SdrzwHRqvULf0sVqvT8JDU6d0q/iPOE8DaONYzimIdgWE9pN88AoZmOudH43J97ZDg1v+Zu76s0tR8YzWHITT1/nbQl53yOfGwDGTRvN6OXdzPLUzTlhftGXeFOFckoD8scQLaZWYhA5ZT4q/9gpM6Yu5M33YRtzjFzN2MeVhZlRey5F56eVp5z2C4Ssg3aBzi2jwgG11czo1PFvWhwmsrCSLZIPwaXWnCxganEfLsyuJrjnUv2QwZzWBOUhF8R7amROqPszTbp4Oree2ZarsN0c3R/7XvboqWaosQkt50Yq8zBCFxrQLfFJ7ZTpHGXCDBksqX8Yekgdqt8H2gRKjv9SKcdcz04keIPB2EO9+fPLw0rFjDeKtQcbdWL9EHtM8p0qpfLsKqGjmwRtxXmTXPsUKAJCTJub8ruQeZlBXYT/ub3D0DuG0vaIMr17h6rtGXGXCXUvULX30gs1rKuTVFdGLEEGbwrGlUTeGGEqPmN1uaf5jDvDuP19GdSWEY1n1N6/WZZ88UKfgdzqIYJzkuG5zlfKQgDDBoesrwpBeydMz43GbdFby/3RoL5\n"
		rawCert, err := base64.StdEncoding.DecodeString(b64EncodedCert)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(rawCert)
		require.NoError(t, err)
		token := JwtX509Token{
			chain: []*x509.Certificate{leaf},
		}

		san, err := token.SubjectAltNameOtherNames()
		require.NoError(t, err)
		require.Len(t, san, 1)
		assert.Equal(t, "2.16.528.1.1007.99.218-1-900021219-N-90000382-00.000-00000000", san[0])
	})

	t.Run("ok - no san in cert", func(t *testing.T) {
		rootCert, _, err := createTestRootCert()
		require.NoError(t, err)
		token := JwtX509Token{
			chain: []*x509.Certificate{rootCert},
		}

		san, err := token.SubjectAltNameOtherNames()
		assert.NoError(t, err)
		assert.Len(t, san, 0)
	})

	t.Run("ok - own certificate", func(t *testing.T) {
		// Create the extension
		otherNameValue, _ := asn1.Marshal("foo:bar")
		othernameExt, err := asn1.Marshal(generalNames{
			OtherName: otherName{
				OID:   asn1.ObjectIdentifier{2, 5, 5, 5},
				Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: otherNameValue},
			}})
		require.NoError(t, err)

		// assemble the certificate template with the extension
		template := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			NotBefore:       time.Now().Add(-10 * time.Second),
			NotAfter:        time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: subjectAltNameID, Value: othernameExt}},
		}

		// generate a private key and create the self signed certificate
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		cert, err := createTestCert(nil, template, &priv.PublicKey, priv)
		require.NoError(t, err)

		token := JwtX509Token{chain: []*x509.Certificate{cert}}
		sans, err := token.SubjectAltNameOtherNames()
		require.NoError(t, err)
		assert.Equal(t, "foo:bar", sans[0])
	})
}

func TestJwtX509Validator_Verify(t *testing.T) {
	rootCert, rootKey, err := createTestRootCert()
	require.NoError(t, err)

	intermediateCert, intermediateKey, err := createIntermediateCert(rootCert, rootKey)
	require.NoError(t, err)

	leafCert, leafKey, err := createLeafCert(intermediateCert, intermediateKey)
	require.NoError(t, err)

	t.Run("ok - valid jwt", func(t *testing.T) {
		db := pki.NewMockValidator(gomock.NewController(t))

		db.EXPECT().Validate([]*x509.Certificate{leafCert, intermediateCert, rootCert}).Return(nil)

		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, []*x509.Certificate{intermediateCert}, []jwa.SignatureAlgorithm{jwa.RS256}, db)

		theJwt := jwt.New()
		theJwt.Set(jwt.IssuedAtKey, time.Now())
		headers := jws.NewHeaders()
		assert.NoError(t, headers.Set(jws.X509CertChainKey, []string{base64.StdEncoding.EncodeToString(leafCert.Raw)}))
		rawJwt, err := jwt.Sign(theJwt, jwa.RS256, leafKey, jwt.WithHeaders(headers))
		require.NoError(t, err)

		x509Token := &JwtX509Token{
			chain:  []*x509.Certificate{leafCert},
			token:  theJwt,
			raw:    string(rawJwt),
			sigAlg: jwa.RS256,
		}
		err = validator.Verify(x509Token)
		assert.NoError(t, err)
	})

	t.Run("nok - signing algorithm not on allowed", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, []*x509.Certificate{intermediateCert}, []jwa.SignatureAlgorithm{jwa.RS256}, nil)
		x509Token := &JwtX509Token{
			sigAlg: jwa.RS512,
		}
		err = validator.Verify(x509Token)
		assert.ErrorContains(t, err, "signature algorithm RS512 is not allowed")
	})

	t.Run("nok - missing iat", func(t *testing.T) {
		validator := NewJwtX509Validator([]*x509.Certificate{rootCert}, []*x509.Certificate{intermediateCert}, []jwa.SignatureAlgorithm{jwa.RS256}, nil)

		theJwt := jwt.New()
		headers := jws.NewHeaders()
		assert.NoError(t, headers.Set(jws.X509CertChainKey, []string{base64.StdEncoding.EncodeToString(leafCert.Raw)}))
		rawJwt, err := jwt.Sign(theJwt, jwa.RS256, leafKey, jwt.WithHeaders(headers))
		require.NoError(t, err)

		x509Token := &JwtX509Token{
			sigAlg: jwa.RS256,
			chain:  []*x509.Certificate{leafCert},
			raw:    string(rawJwt),
			token:  theJwt,
		}

		err = validator.Verify(x509Token)
		assert.ErrorContains(t, err, "jwt must have an issued at (iat) field")
	})
}

func NewMockValidator(t *testing.T, rootCert, intermediateCert, leafCert *x509.Certificate, intermediateRevoked bool) pki.Validator {
	db := pki.NewMockValidator(gomock.NewController(t))

	if intermediateRevoked {
		db.EXPECT().Validate([]*x509.Certificate{leafCert, intermediateCert, rootCert}).Return(pki.ErrCertRevoked)
	} else {
		db.EXPECT().Validate([]*x509.Certificate{leafCert, intermediateCert, rootCert}).Return(nil)
	}

	return db
}

func TestJwtX509Validator_checkCertRevocation(t *testing.T) {
	t.Run("no crls in chain", func(t *testing.T) {
		rootCert, rootCertKey, err := createTestRootCert()
		require.NoError(t, err)

		intermediateCert, intermediateCerKey, err := createIntermediateCert(rootCert, rootCertKey)
		require.NoError(t, err)

		leafCert, _, err := createLeafCert(intermediateCert, intermediateCerKey)
		require.NoError(t, err)

		t.Run("ok", func(t *testing.T) {
			validator := NewJwtX509Validator(
				[]*x509.Certificate{rootCert},
				[]*x509.Certificate{intermediateCert},
				[]jwa.SignatureAlgorithm{jwa.RS256},
				NewMockValidator(t, rootCert, intermediateCert, leafCert, false),
			)
			assert.NoError(t, validator.checkCertRevocation([]*x509.Certificate{leafCert, intermediateCert, rootCert}))
		})
	})

	t.Run("with crl", func(t *testing.T) {
		crlUrl := "http://example.com/cert.crl"

		rootCert, rootCertKey, err := createTestRootCert()
		require.NoError(t, err)

		intermediateCert, intermediateCerKey, err := createIntermediateCertWithCrl(rootCert, rootCertKey, crlUrl)
		require.NoError(t, err)

		leafCert, _, err := createLeafCert(intermediateCert, intermediateCerKey)
		require.NoError(t, err)

		t.Run("ok - this intermediate is not revoked", func(t *testing.T) {
			intermediateCert, intermediateCerKey, err := createIntermediateCertWithCrl(rootCert, rootCertKey, crlUrl)
			require.NoError(t, err)

			leafCert, _, err := createLeafCert(intermediateCert, intermediateCerKey)
			require.NoError(t, err)

			validator := NewJwtX509Validator(
				[]*x509.Certificate{rootCert},
				[]*x509.Certificate{intermediateCert},
				[]jwa.SignatureAlgorithm{jwa.RS256},
				NewMockValidator(t, rootCert, intermediateCert, leafCert, false),
			)

			err = validator.checkCertRevocation([]*x509.Certificate{leafCert, intermediateCert, rootCert})
			assert.NoError(t, err)
		})

		t.Run("nok - intermediate is revoked", func(t *testing.T) {
			validator := NewJwtX509Validator(
				[]*x509.Certificate{rootCert},
				[]*x509.Certificate{intermediateCert},
				[]jwa.SignatureAlgorithm{jwa.RS256},
				NewMockValidator(t, rootCert, intermediateCert, leafCert, true),
			)

			err = validator.checkCertRevocation([]*x509.Certificate{leafCert, intermediateCert, rootCert})
			assert.ErrorIs(t, err, pki.ErrCertRevoked)
		})
	})
}
