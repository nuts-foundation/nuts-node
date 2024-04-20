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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMemoryKeyStore_Decrypt(t *testing.T) {
	_, err := MemoryKeyStore{}.Decrypt(context.Background(), "", nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_DecryptJWE(t *testing.T) {
	_, _, err := MemoryKeyStore{}.DecryptJWE(context.Background(), "")
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_Delete(t *testing.T) {
	err := MemoryKeyStore{}.Delete(context.Background(), "")
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_EncryptJWE(t *testing.T) {
	_, err := MemoryKeyStore{}.EncryptJWE(context.Background(), nil, nil, nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_New(t *testing.T) {
	_, err := MemoryKeyStore{}.New(context.Background(), nil)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_Exists(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := jwk.FromRaw(pk)
	key.Set(jwk.KeyIDKey, "123")
	t.Run("does not exist", func(t *testing.T) {
		assert.False(t, MemoryKeyStore{Key: key}.Exists(context.Background(), ""))
	})
	t.Run("exists", func(t *testing.T) {
		assert.True(t, MemoryKeyStore{
			Key: key,
		}.Exists(context.Background(), "123"))
	})
}

func TestMemoryKeyStore_List(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := jwk.FromRaw(pk)
	key.Set(jwk.KeyIDKey, "123")
	assert.Equal(t, []string{"123"}, MemoryKeyStore{Key: key}.List(context.Background()))
}

func TestMemoryKeyStore_Resolve(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := jwk.FromRaw(pk)
	key.Set(jwk.KeyIDKey, "123")
	t.Run("not found", func(t *testing.T) {
		_, err := MemoryKeyStore{key}.Resolve(context.Background(), "456")
		assert.ErrorIs(t, err, ErrPrivateKeyNotFound)
	})
	t.Run("found", func(t *testing.T) {
		k, err := MemoryKeyStore{
			Key: key,
		}.Resolve(context.Background(), "123")
		assert.NoError(t, err)
		assert.Equal(t, "123", k.KID())
	})
}

func TestMemoryKeyStore_SignJWS(t *testing.T) {
	_, err := MemoryKeyStore{}.SignJWS(context.Background(), nil, nil, nil, false)
	assert.ErrorIs(t, err, errNotSupportedForInMemoryKeyStore)
}

func TestMemoryKeyStore_SignJWT(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKeyJWK, _ := jwk.FromRaw(pk)
	privateKeyJWK.Set(jwk.KeyIDKey, "123")
	alg, _ := ecAlg(pk)
	privateKeyJWK.Set(jwk.AlgorithmKey, alg)

	t.Run("ok", func(t *testing.T) {
		signedJWT, err := MemoryKeyStore{
			Key: privateKeyJWK,
		}.SignJWT(context.Background(), nil, nil, &basicKey{kid: "123"})
		assert.NoError(t, err)
		assert.NotEmpty(t, signedJWT)
	})
	t.Run("unknown key", func(t *testing.T) {
		_, err := MemoryKeyStore{
			Key: privateKeyJWK,
		}.SignJWT(context.Background(), nil, nil, &basicKey{kid: "456"})
		assert.ErrorIs(t, err, ErrPrivateKeyNotFound)
	})
}
