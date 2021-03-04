/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/test"
)

func TestSignJWT(t *testing.T) {
	claims := map[string]interface{}{"iss": "nuts"}
	t.Run("creates valid JWT using rsa keys", func(t *testing.T) {
		rsaKey := test.GenerateRSAKey()
		key, _ := jwkKey(rsaKey)
		tokenString, err := SignJWT(key, claims, nil)

		assert.Nil(t, err)

		token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
			return rsaKey.Public(), nil
		})

		if !assert.NoError(t, err) {
			return
		}

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
				tokenString, err := SignJWT(key, claims, nil)

				if !assert.NoError(t, err) {
					return
				}

				token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
					return ecKey.Public(), nil
				})

				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, "nuts", token.Issuer())
			})
		}
	})

	t.Run("sets correct headers", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, _ := jwkKey(ecKey)
		tokenString, err := SignJWT(key, claims, nil)

		if !assert.NoError(t, err) {
			return
		}

		msg, err := jws.ParseString(tokenString)
		if !assert.NoError(t, err) {
			return
		}
		hdrs := msg.Signatures()[0].ProtectedHeaders()
		alg, _ := hdrs.Get(jwk.AlgorithmKey)
		assert.Equal(t, jwa.ES256, alg)
	})

	t.Run("invalid claim", func(t *testing.T) {
		tokenString, err := SignJWT(nil, map[string]interface{}{jwt.IssuedAtKey: "foobar"}, nil)
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
}

func TestCrypto_SignJWT(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	key, _, _ := client.New(StringNamingFunc(kid))

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, kid)
		println(tokenString)

		if !assert.NoError(t, err) {
			return
		}

		token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
			return key, nil
		})

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "nuts", token.Issuer())
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, "unknown")

		assert.True(t, errors.Is(err, ErrKeyNotFound))
	})
}

func TestCrypto_SignJWS(t *testing.T) {
	client := createCrypto(t)
	kid := "kid"
	publicKey, _, _ := client.New(StringNamingFunc(kid))

	t.Run("ok", func(t *testing.T) {
		payload := []byte{1, 2, 3}
		hdrs := map[string]interface{}{"foo": "bar"}
		signature, err := client.SignJWS(payload, hdrs, kid)
		if !assert.NoError(t, err) {
			return
		}
		message, err := jws.Parse([]byte(signature))
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, message.Payload())
		sig := message.Signatures()
		assert.Len(t, sig, 1)
		fooValue, _ := sig[0].ProtectedHeaders().Get("foo")
		assert.Equal(t, "bar", fooValue.(string))
		// Sanity check: verify signature
		actualPayload, err := jws.Verify([]byte(signature), sig[0].ProtectedHeaders().Algorithm(), publicKey)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, actualPayload)
	})
	t.Run("public key as JWK", func(t *testing.T) {
		payload := []byte{1, 2, 3}

		publicKeyAsJWK, _ := jwk.New(publicKey)
		hdrs := map[string]interface{}{"jwk": publicKeyAsJWK}
		signature, err := client.SignJWS(payload, hdrs, kid)
		assert.NoError(t, err)
		assert.NotEmpty(t, signature)
	})
	t.Run("private key as JWK (disallowed)", func(t *testing.T) {
		payload := []byte{1, 2, 3}

		privateKey, _ := client.Storage.GetPrivateKey(kid)
		privateKeyAsJWK, _ := jwk.New(privateKey)
		hdrs := map[string]interface{}{"jwk": privateKeyAsJWK}
		signature, err := client.SignJWS(payload, hdrs, kid)
		assert.EqualError(t, err, "refusing to sign JWS with private key in JWK header")
		assert.Empty(t, signature)
	})
	t.Run("invalid header", func(t *testing.T) {
		payload := []byte{1, 2, 3}
		signature, err := client.SignJWS(payload, map[string]interface{}{"jwk": "invalid jwk"}, kid)
		assert.EqualError(t, err, "unable to set header jwk: invalid value for jwk key: string")
		assert.Empty(t, signature)
	})
	t.Run("unknown key", func(t *testing.T) {
		payload := []byte{1, 2, 3}
		signature, err := client.SignJWS(payload, map[string]interface{}{}, "unknown")
		assert.Contains(t, err.Error(), "error while signing JWS, can't get private key")
		assert.Empty(t, signature)
	})
}

func TestCrypto_SignDetachedJWS(t *testing.T) {
	client := createCrypto(t)
	kid := "kid"
	publicKey, _, _ := client.New(StringNamingFunc(kid))
	payload := []byte{1, 2, 3}

	t.Run("ok", func(t *testing.T) {
		jwsString, err := client.SignDetachedJWS(payload, kid)
		if !assert.NoError(t, err) {
			return
		}

		t.Run("ok - correct headers", func(t *testing.T) {
			i := strings.Index(jwsString, "..")
			headers := jwsString[0:i]
			j, _ := base64.StdEncoding.DecodeString(headers)
			var m = make(map[string]interface{})
			json.Unmarshal(j, &m)

			assert.Len(t, m, 3)
			assert.Equal(t, "ES256", m["alg"])
			assert.Equal(t, []interface{}{"b64"}, m["crit"])
			assert.Equal(t, false, m["b64"])
		})

		t.Run("ok - correct signature", func(t *testing.T) {
			i := strings.Index(jwsString, "..")
			sig, _ := base64.StdEncoding.DecodeString(jwsString[i+2:])
			v, _ := jws.NewVerifier(jwa.ES256)

			err = v.Verify(payload, sig, publicKey)

			assert.NoError(t, err)
		})
	})

	t.Run("error - unknown key", func(t *testing.T) {
		_, err := client.SignDetachedJWS(payload, "kid2")

		assert.Error(t, err)
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
