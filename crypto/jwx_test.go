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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	rsa2 "crypto/rsa"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestSignJWT(t *testing.T) {
	claims := map[string]interface{}{"iss": "nuts"}
	t.Run("creates valid JWT using rsa keys", func(t *testing.T) {
		key, _ := rsa2.GenerateKey(rand.Reader, 2048)
		tokenString, err := SignJWT(key, claims, nil)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return key.Public(), nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("creates valid JWT using ec keys", func(t *testing.T) {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

		keys := []*ecdsa.PrivateKey{p256, p384, p521}

		for _, key := range keys {
			name := fmt.Sprintf("using %s", key.Params().Name)
			t.Run(name, func(t *testing.T) {
				tokenString, err := SignJWT(key, claims, nil)

				if assert.Nil(t, err) {
					token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
						return key.Public(), nil
					})

					if assert.Nil(t, err) {
						assert.True(t, token.Valid)
						assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
					}
				}
			})
		}
	})

	t.Run("sets correct headers", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ := SignJWT(key, claims, map[string]interface{}{"x5c": []string{"BASE64"}})
		token, _ := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
			return key.Public(), nil
		})

		assert.Equal(t, "JWT", token.Header["typ"])
		assert.Equal(t, "ES256", token.Header["alg"])
		assert.Equal(t, []interface{}{"BASE64"}, token.Header["x5c"])
	})

	t.Run("returns error on unknown curve", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		_, err := SignJWT(key, claims, nil)

		assert.NotNil(t, err)
	})

	t.Run("returns error on unsupported crypto", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		_, err := SignJWT(key, claims, nil)

		assert.NotNil(t, err)
	})
}

func TestCrypto_PublicKeyInJWK(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	publicKey, _ := client.GenerateKeyPair()
	kid, _ := util.Fingerprint(publicKey)

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.GetPublicKey(kid)

		assert.NoError(t, err)
		assert.NotNil(t, pub)

		jwkKey, _ := jwk.New(pub)

		assert.Equal(t, jwa.EC, jwkKey.KeyType())
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		_, err := client.GetPublicKey("unknown")

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_SignJWT(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	publicKey, _ := client.GenerateKeyPair()
	kid, _ := util.Fingerprint(publicKey)

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, kid)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			pubKey, _ := client.Storage.GetPublicKey(kid)
			return pubKey, nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, "unknown")

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}
