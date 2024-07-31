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

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/nuts-foundation/nuts-node/audit"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestMemoryKeyStore_SignJWT(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKeyJWK, _ := jwk.FromRaw(pk)
	privateKeyJWK.Set(jwk.KeyIDKey, "123")
	alg, _ := ecAlgUsingPublicKey(pk.PublicKey)
	privateKeyJWK.Set(jwk.AlgorithmKey, alg)

	t.Run("ok", func(t *testing.T) {
		signedJWT, err := MemoryJWTSigner{
			Key: privateKeyJWK,
		}.SignJWT(audit.TestContext(), nil, nil, "123")
		assert.NoError(t, err)
		assert.NotEmpty(t, signedJWT)
	})
	t.Run("unknown key", func(t *testing.T) {
		_, err := MemoryJWTSigner{
			Key: privateKeyJWK,
		}.SignJWT(audit.TestContext(), nil, nil, "456")
		assert.ErrorIs(t, err, ErrPrivateKeyNotFound)
	})
}

func TestMemoryJWTSigner_SignJWS(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKeyJWK, _ := jwk.FromRaw(pk)
	privateKeyJWK.Set(jwk.KeyIDKey, "123")
	alg, _ := ecAlgUsingPublicKey(pk.PublicKey)
	privateKeyJWK.Set(jwk.AlgorithmKey, alg)
	payload := []byte("{}")
	headers := map[string]interface{}{}

	t.Run("ok", func(t *testing.T) {
		signedJWT, err := MemoryJWTSigner{
			Key: privateKeyJWK,
		}.SignJWS(audit.TestContext(), payload, headers, "123", false)
		assert.NoError(t, err)
		assert.NotEmpty(t, signedJWT)
	})
	t.Run("unknown key", func(t *testing.T) {
		_, err := MemoryJWTSigner{
			Key: privateKeyJWK,
		}.SignJWS(audit.TestContext(), payload, headers, "456", false)
		assert.ErrorIs(t, err, ErrPrivateKeyNotFound)
	})
}
