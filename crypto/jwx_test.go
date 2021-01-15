/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
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

		hdrs := msg.Signatures()[0].ProtectedHeaders()
		alg, _ := hdrs.Get(jwk.AlgorithmKey)
		assert.Equal(t, jwa.ES256, alg)
	})
}

func TestCrypto_SignJWT(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	client.New(StringNamingFunc(kid))

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, kid)
		println(tokenString)

		if !assert.NoError(t, err) {
			return
		}

		token, err := ParseJWT(tokenString, func(kid string) (crypto.PublicKey, error) {
			return client.GetPublicKey(kid)
		})

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "nuts", token.Issuer())
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, "unknown")

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}

func TestCrypto_convertHeaders(t *testing.T) {
	t.Run("nil headers", func(t *testing.T) {
		jwtHeader := convertHeaders(nil)
		assert.Len(t, jwtHeader.PrivateParams(), 0)
	})

	t.Run("ok", func(t *testing.T) {
		rawHeaders := map[string]interface{} {
			"key": "value",
		}

		jwtHeader := convertHeaders(rawHeaders)
		v, _ := jwtHeader.Get("key")
		assert.Equal(t, "value", v)
	})
}
