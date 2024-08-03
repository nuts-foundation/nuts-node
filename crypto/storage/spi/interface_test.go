/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package spi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicKeyEntry_UnmarshalJSON(t *testing.T) {
	t.Run("error - incorrect json", func(t *testing.T) {
		err := (&PublicKeyEntry{}).UnmarshalJSON([]byte("}"))
		assert.EqualError(t, err, "invalid character '}' looking for beginning of value")
	})

	t.Run("error - invalid publicKeyJwk format", func(t *testing.T) {
		err := (&PublicKeyEntry{}).UnmarshalJSON([]byte("{\"publicKeyJwk\":{}}"))
		assert.EqualError(t, err, "could not parse publicKeyEntry: invalid publickeyJwk: invalid key type from JSON ()")
	})
}

func TestPublicKeyEntry_FromJWK(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := jwk.FromRaw(privateKey)

	entry := PublicKeyEntry{}
	err := entry.FromJWK(pk)
	require.NoError(t, err)
	assert.NotEmpty(t, entry.Key)
	assert.Same(t, pk, entry.parsedJWK)
}

func TestGenerateKeyPairAndKID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keyPair, err := GenerateKeyPair()
		require.NoError(t, err)
		assert.NotNil(t, keyPair)
	})
}

func TestGenerateAndStore(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockStorage(ctrl)
		store.EXPECT().PrivateKeyExists(ctx, "123", "1").Return(false, nil)
		store.EXPECT().SavePrivateKey(ctx, gomock.Any(), gomock.Any()).Return(nil)
		keyName := "123"

		key, version, err := GenerateAndStore(ctx, store, keyName)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "1", version)
	})

	t.Run("error - save public key returns an error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockStorage(ctrl)
		store.EXPECT().PrivateKeyExists(ctx, "123", "1").Return(false, nil)
		store.EXPECT().SavePrivateKey(ctx, gomock.Any(), gomock.Any()).Return(errors.New("foo"))
		keyName := "123"

		_, _, err := GenerateAndStore(ctx, store, keyName)

		assert.ErrorContains(t, err, "could not create new keypair: could not save private key: foo")
	})

	t.Run("error - ID already in use", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockStorage(ctrl)
		store.EXPECT().PrivateKeyExists(ctx, "123", "1").Return(true, nil)
		keyName := "123"

		_, _, err := GenerateAndStore(ctx, store, keyName)

		assert.ErrorContains(t, err, "key with the given ID already exists")
	})
}
