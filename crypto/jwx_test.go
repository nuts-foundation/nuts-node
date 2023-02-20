/*
 * Nuts node
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
 */

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/shengdoushi/base58"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/test"
)

func TestSignJWT(t *testing.T) {
	claims := map[string]interface{}{"iss": "nuts"}
	t.Run("creates valid JWT using rsa keys", func(t *testing.T) {
		rsaKey := test.GenerateRSAKey()
		key, _ := jwkKey(rsaKey)
		tokenString, err := signJWT(key, claims, nil)

		assert.Nil(t, err)

		token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
			return rsaKey.Public(), nil
		})

		require.NoError(t, err)

		assert.Equal(t, "nuts", token.Issuer())
	})

	t.Run("creates valid JWT using ec keys", func(t *testing.T) {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

		keys := []*ecdsa.PrivateKey{p256, p384, p521}

		for _, ecKey := range keys {
			name := fmt.Sprintf("using %s", ecKey.Params().Name)
			t.Run(name, func(t *testing.T) {
				key, _ := jwkKey(ecKey)
				tokenString, err := signJWT(key, claims, nil)

				require.NoError(t, err)

				token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
					return ecKey.Public(), nil
				})

				require.NoError(t, err)
				assert.Equal(t, "nuts", token.Issuer())
			})
		}
	})

	t.Run("sets correct headers", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, _ := jwkKey(ecKey)
		tokenString, err := signJWT(key, claims, nil)

		require.NoError(t, err)

		msg, err := jws.ParseString(tokenString)
		require.NoError(t, err)
		hdrs := msg.Signatures()[0].ProtectedHeaders()
		alg, _ := hdrs.Get(jwk.AlgorithmKey)
		assert.Equal(t, jwa.ES256, alg)
	})

	t.Run("invalid claim", func(t *testing.T) {
		tokenString, err := signJWT(nil, map[string]interface{}{jwt.IssuedAtKey: "foobar"}, nil)
		assert.Empty(t, tokenString)
		assert.EqualError(t, err, "invalid value for iat key: invalid epoch value \"foobar\"")
	})
}

func TestParseJWT(t *testing.T) {
	t.Run("unsupported algorithm", func(t *testing.T) {
		rsaKey := test.GenerateRSAKey()
		token := jwt.New()
		signature, _ := jwt.Sign(token, jwa.RS256, rsaKey)
		parsedToken, err := ParseJWT(string(signature), func(_ string) (crypto.PublicKey, error) {
			return rsaKey.Public(), nil
		})
		assert.Nil(t, parsedToken)
		assert.EqualError(t, err, "token signing algorithm is not supported: RS256")
	})

	t.Run("allow clock skew", func(t *testing.T) {
		ecKey := test.GenerateECKey()
		token := jwt.New()
		err := token.Set(jwt.IssuedAtKey, time.Now().Add(4*time.Second).Unix())
		assert.NoError(t, err)
		signature, _ := jwt.Sign(token, jwa.ES256, ecKey)
		parsedToken, err := ParseJWT(string(signature), func(_ string) (crypto.PublicKey, error) {
			return ecKey.Public(), nil
		}, jwt.WithAcceptableSkew(5000*time.Millisecond))
		require.NoError(t, err)

		assert.NotNil(t, parsedToken)
	})
}

func TestCrypto_SignJWT(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	key, _ := client.New(audit.TestContext(), StringNamingFunc(kid))

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWT(audit.TestContext(), map[string]interface{}{"iss": "nuts", "sub": "subject"}, key)

		require.NoError(t, err)

		var actualKID string
		token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
			actualKID = kid
			return key.Public(), nil
		})

		require.NoError(t, err)

		assert.Equal(t, "nuts", token.Issuer())
		assert.Equal(t, kid, actualKID)
	})
	t.Run("writes audit logs", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)

		_, err := client.SignJWT(audit.TestContext(), map[string]interface{}{"iss": "nuts", "sub": "subject"}, key)

		require.NoError(t, err)
		auditLogs.AssertContains(t, ModuleName, "SignJWT", audit.TestActor, "Signing a JWT with key: kid (issuer: nuts, subject: subject)")
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJWT(audit.TestContext(), map[string]interface{}{"iss": "nuts"}, basicKey{kid: "unknown"})

		assert.True(t, errors.Is(err, ErrPrivateKeyNotFound))
	})

	t.Run("returns error for invalid KID", func(t *testing.T) {
		_, err := client.SignJWT(audit.TestContext(), map[string]interface{}{"iss": "nuts"}, basicKey{kid: "../certificate"})

		assert.ErrorContains(t, err, "invalid key ID")
	})
}

func TestCrypto_SignJWS(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	key, _ := client.New(audit.TestContext(), StringNamingFunc(kid))

	t.Run("creates valid JWS", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		tokenString, err := client.SignJWS(audit.TestContext(), payload, map[string]interface{}{"typ": "JWT"}, key, false)

		require.NoError(t, err)

		token, err := ParseJWS([]byte(tokenString), func(kid string) (crypto.PublicKey, error) {
			return key.Public(), nil
		})
		require.NoError(t, err)

		var body = make(map[string]interface{})
		err = json.Unmarshal(token, &body)

		require.NoError(t, err)

		assert.Equal(t, "nuts", body["iss"])
	})
	t.Run("writes audit log", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)

		_, err := client.SignJWS(audit.TestContext(), []byte{1, 2, 3}, map[string]interface{}{"typ": "JWT"}, key, false)

		require.NoError(t, err)
		auditLogs.AssertContains(t, ModuleName, "SignJWS", audit.TestActor, "Signing a JWS with key: kid")
	})

	t.Run("returns error for not found", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		_, err := client.SignJWS(audit.TestContext(), payload, map[string]interface{}{"typ": "JWT"}, basicKey{kid: "unknown"}, false)

		assert.True(t, errors.Is(err, ErrPrivateKeyNotFound))
	})

	t.Run("returns error for invalid KID", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		_, err := client.SignJWS(audit.TestContext(), payload, map[string]interface{}{"typ": "JWT"}, basicKey{kid: "../certificate"}, false)

		assert.ErrorContains(t, err, "invalid key ID")
	})
}

func TestCrypto_EncryptJWE(t *testing.T) {
	client := createCrypto(t)

	kid := "did:nuts:1234"
	key, _ := client.New(audit.TestContext(), StringNamingFunc(kid))
	public := key.Public()

	headers := map[string]interface{}{"typ": "JWT"}
	t.Run("creates valid JWE", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		tokenString, err := client.EncryptJWE(audit.TestContext(), payload, headers, public, kid)

		require.NoError(t, err)

		privateKey, _, err := client.getPrivateKey(key)
		require.NoError(t, err)

		token, err := jwe.Decrypt([]byte(tokenString), jwa.ECDH_ES, privateKey)
		require.NoError(t, err)

		var body = make(map[string]interface{})
		err = json.Unmarshal(token, &body)

		require.NoError(t, err)

		assert.Equal(t, "nuts", body["iss"])
	})
	t.Run("creates valid JWE, alt alg", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		headers := map[string]interface{}{"typ": "JWT", "alg": "ECDH-ES"}
		tokenString, err := client.EncryptJWE(audit.TestContext(), payload, headers, public, kid)

		require.NoError(t, err)

		privateKey, _, err := client.getPrivateKey(key)
		require.NoError(t, err)

		token, err := jwe.Decrypt([]byte(tokenString), jwa.ECDH_ES, privateKey)
		require.NoError(t, err)

		var body = make(map[string]interface{})
		err = json.Unmarshal(token, &body)

		require.NoError(t, err)

		assert.Equal(t, "nuts", body["iss"])
	})
	t.Run("creates valid JWE, alt enc", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		headers := map[string]interface{}{"typ": "JWT", "enc": "A256CBC-HS512"}
		tokenString, err := client.EncryptJWE(audit.TestContext(), payload, headers, public, kid)

		require.NoError(t, err)

		privateKey, _, err := client.getPrivateKey(key)
		require.NoError(t, err)

		token, err := jwe.Decrypt([]byte(tokenString), jwa.ECDH_ES, privateKey)
		require.NoError(t, err)

		var body = make(map[string]interface{})
		err = json.Unmarshal(token, &body)

		require.NoError(t, err)

		assert.Equal(t, "nuts", body["iss"])
	})
	t.Run("creates broken JWE, enc header", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
		headers := map[string]interface{}{"typ": "JWT", "enc" : "ECDH-ES"}
		_, err := client.EncryptJWE(audit.TestContext(), payload, headers, public, kid)
		require.Error(t, err)
	})
	t.Run("writes audit log", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)

		_, err := client.EncryptJWE(audit.TestContext(), []byte{1, 2, 3}, headers, public, kid)

		require.NoError(t, err)
		auditLogs.AssertContains(t, ModuleName, "EncryptJWE", audit.TestActor,  fmt.Sprintf("Encrypting a JWE with key: %s", kid))
	})
}

func TestCrypto_DecryptJWE(t *testing.T) {
	client := createCrypto(t)

	kid := "did:nuts:1234"
	key, _ := client.New(audit.TestContext(), StringNamingFunc(kid))

	t.Run("decrypts valid JWE", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})

		tokenString, err := EncryptJWE(payload, map[string]interface{}{"typ": "JWT", "kid": kid}, key.Public())

		require.NoError(t, err)


		token, hdrs, err := client.DecryptJWE(audit.TestContext(), tokenString)
		require.NoError(t, err)

		var body = make(map[string]interface{})
		err = json.Unmarshal(token, &body)


		require.NoError(t, err)

		assert.Equal(t, "nuts", body["iss"])
		assert.Equal(t, "JWT", hdrs["typ"])
	})
	t.Run("writes audit log", func(t *testing.T) {
		auditLogs := audit.CaptureLogs(t)

		tokenString, err := EncryptJWE([]byte{1, 2, 3}, map[string]interface{}{"typ": "JWT", "kid": kid}, key.Public())
		require.NoError(t, err)
		_, _, err = client.DecryptJWE(audit.TestContext(), tokenString)

		require.NoError(t, err)

		auditLogs.AssertContains(t, ModuleName, "DecryptJWE", audit.TestActor,  fmt.Sprintf("Decrypting a JWE with kid: %s", kid))
	})
}

func TestSignJWS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("attached", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			payload := []byte{1, 2, 3}
			hdrs := map[string]interface{}{"foo": "bar"}
			signature, err := signJWS(payload, hdrs, key, false)
			require.NoError(t, err, "error during signing")
			message, err := jws.Parse([]byte(signature))
			require.NoError(t, err, "error during parsing sign result as jws")
			assert.Equal(t, payload, message.Payload(),
				"parsed message not equal to original payload")
			sig := message.Signatures()
			assert.Len(t, sig, 1,
				"there must be one signature in the parsed message")
			fooValue, _ := sig[0].ProtectedHeaders().Get("foo")
			assert.Equal(t, "bar", fooValue.(string),
				"the protected headers must contain the 'foo' key with 'bar' value")

			// Sanity check: verify signature
			actualPayload, err := jws.Verify([]byte(signature), sig[0].ProtectedHeaders().Algorithm(), key.Public())
			require.NoError(t, err, "the signature could not be validated")
			assert.Equal(t, payload, actualPayload)
		})
		t.Run("public key in JWK header is allowed", func(t *testing.T) {
			payload := []byte{1, 2, 3}

			publicKeyAsJWK, _ := jwk.New(key.Public())
			hdrs := map[string]interface{}{"jwk": publicKeyAsJWK}
			signature, err := signJWS(payload, hdrs, key, false)
			assert.NoError(t, err)
			assert.NotEmpty(t, signature)
		})
		t.Run("it fails with an invalid payload", func(t *testing.T) {
			// set b64 to false to indicate the payload should not be base64 encoded
			hdrs := map[string]interface{}{"b64": false}
			// a dot is an invalid character when nog base64 encoded
			payload := []byte{'.'}

			signature, err := signJWS(payload, hdrs, key, false)
			assert.EqualError(t, err, "unable to sign JWS failed sign payload: payload must not contain a \".\"")
			assert.Empty(t, signature)
		})
		t.Run("private key in JWK header is not allowed", func(t *testing.T) {
			payload := []byte{1, 2, 3}

			privateKeyAsJWK, _ := jwk.New(key)
			hdrs := map[string]interface{}{"jwk": privateKeyAsJWK}
			signature, err := signJWS(payload, hdrs, key, false)
			assert.EqualError(t, err, "refusing to sign JWS with private key in JWK header")
			assert.Empty(t, signature)
		})

		t.Run("it checks the headers", func(t *testing.T) {
			t.Run("it fails with an invalid jwk format", func(t *testing.T) {
				payload := []byte{1, 2, 3}
				signature, err := signJWS(payload, map[string]interface{}{"jwk": "invalid jwk"}, key, false)
				assert.EqualError(t, err, "unable to set header jwk: invalid value for jwk key: string")
				assert.Empty(t, signature)
			})
		})
		t.Run("it fails with an invalid key", func(t *testing.T) {
			payload := []byte{1, 2, 3}

			publicKeyAsJWK, _ := jwk.New(key.Public())
			hdrs := map[string]interface{}{"jwk": publicKeyAsJWK}
			signature, err := signJWS(payload, hdrs, nil, false)
			assert.EqualError(t, err, "jwk.New requires a non-nil key")
			assert.Empty(t, signature)
		})
	})
	t.Run("detached", func(t *testing.T) {
		t.Run("it can sign with a detached payload", func(t *testing.T) {
			payload := []byte{1, 2, 3}
			signature, err := signJWS(payload, map[string]interface{}{"b64": false}, key, true)
			assert.NoError(t, err, "no error expected")
			assert.Contains(t, signature, "..")
		})
	})

}

func TestCrypto_convertHeaders(t *testing.T) {
	t.Run("nil headers", func(t *testing.T) {
		jwtHeader := convertHeaders(nil)
		assert.Len(t, jwtHeader.PrivateParams(), 0)
	})

	t.Run("ok", func(t *testing.T) {
		rawHeaders := map[string]interface{}{
			"key": "value",
		}

		jwtHeader := convertHeaders(rawHeaders)
		v, _ := jwtHeader.Get("key")
		assert.Equal(t, "value", v)
	})
}

func Test_isAlgorithmSupported(t *testing.T) {
	assert.True(t, isAlgorithmSupported(jwa.PS256))
	assert.False(t, isAlgorithmSupported(jwa.RS256))
	assert.False(t, isAlgorithmSupported(""))
}

func TestSignatureAlgorithm(t *testing.T) {
	ecKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKey521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	pEDKey, sEDKey, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("no key", func(t *testing.T) {
		_, err := SignatureAlgorithm(nil)

		assert.Error(t, err)
	})

	t.Run("unsupported key", func(t *testing.T) {
		ecKey224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		_, err := SignatureAlgorithm(ecKey224)

		assert.Equal(t, ErrUnsupportedSigningKey, err)
	})

	tests := []struct {
		name string
		key  interface{}
		alg  jwa.SignatureAlgorithm
	}{
		{"EC private key as pointer", ecKey256, jwa.ES256},
		{"EC private key", *ecKey256, jwa.ES256},
		{"EC public key as pointer", &ecKey384.PublicKey, jwa.ES384},
		{"EC public key", ecKey521.PublicKey, jwa.ES512},
		{"RSA private key as pointer", rsaKey, jwa.PS256},
		{"RSA private key", *rsaKey, jwa.PS256},
		{"RSA public key as pointer", &rsaKey.PublicKey, jwa.PS256},
		{"RSA public key", rsaKey.PublicKey, jwa.PS256},
		{"ED25519 private key", pEDKey, jwa.EdDSA},
		{"ED25519 public key", sEDKey, jwa.EdDSA},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alg, err := SignatureAlgorithm(test.key)

			require.NoError(t, err)
			assert.Equal(t, test.alg, alg)
		})
	}
}

func TestThumbprint(t *testing.T) {
	t.Run("rsa", func(t *testing.T) {
		// example from https://tools.ietf.org/html/rfc7638#page-3
		testRsa := "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}"
		expectedThumbPrint := base58.Encode([]byte{55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123}, base58.BitcoinAlphabet)

		set, err := jwk.ParseString(testRsa)
		require.NoError(t, err)

		key, _ := set.Get(0)
		thumbPrint, err := Thumbprint(key)
		require.NoError(t, err)

		assert.Equal(t, expectedThumbPrint, thumbPrint)
	})
	t.Run("ec", func(t *testing.T) {
		testEC := `{"crv":"P-256","kid":"did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="}`
		expectedThumbPrint := "3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn"

		set, err := jwk.ParseString(testEC)
		require.NoError(t, err)

		key, _ := set.Get(0)
		thumbPrint, err := Thumbprint(key)
		require.NoError(t, err)

		assert.Equal(t, expectedThumbPrint, thumbPrint)
	})
}
