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
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/stretchr/testify/assert"
)

func TestCrypto_PublicKey(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	ec := test.GenerateECKey()

	now := time.Now()
	period := core.Period{Begin: now}
	client.SavePublicKey(kid, ec.Public(), period)

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.GetPublicKey(kid, now)

		assert.Nil(t, err)
		assert.NotEmpty(t, pub)
	})

	t.Run("error - unknown", func(t *testing.T) {
		_, err := client.GetPublicKey("unknown", now)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("error - kid not valid at time", func(t *testing.T) {
		_, err := client.GetPublicKey(kid, now.Add(-1))

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("error - saving an empty key", func(t *testing.T) {
		err := client.SavePublicKey(kid, nil, period)
		assert.Error(t, err)
	})
}

func TestCrypto_KeyExistsFor(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	client.New(StringNamingFunc(kid))

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.PrivateKeyExists(kid))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.PrivateKeyExists("unknown"))
	})
}

func TestCrypto_New(t *testing.T) {
	client := createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		kid := "kid"
		publicKey, returnKid, err := client.New(StringNamingFunc(kid))
		assert.NoError(t, err)
		assert.NotNil(t, publicKey)
		assert.Equal(t, kid, returnKid)
	})

	t.Run("error - NamingFunction returns err", func(t *testing.T) {
		errorNamingFunc := func(key crypto.PublicKey) (string, error) {
			return "", errors.New("b00m!")
		}
		_, _, err := client.New(errorNamingFunc)
		assert.Error(t, err)
	})
}

func TestCrypto_Configure(t *testing.T) {
	directory := io.TestDirectory(t)
	cfg := core.NutsConfig{Datadir: directory}
	t.Run("ok", func(t *testing.T) {
		e := createCrypto(t)
		err := e.Configure(cfg)
		assert.NoError(t, err)
	})
	t.Run("ok - default = fs backend", func(t *testing.T) {
		client := createCrypto(t)
		err := client.Configure(cfg)
		if !assert.NoError(t, err) {
			return
		}
		storageType := reflect.TypeOf(client.Storage).String()
		assert.Equal(t, "*storage.fileSystemBackend", storageType)
	})
	t.Run("error - unknown backend", func(t *testing.T) {
		client := createCrypto(t)
		client.config.Storage = "unknown"
		err := client.Configure(cfg)
		assert.EqualErrorf(t, err, "only fs backend available for now", "expected error")
	})
}

func TestNewCryptoInstance(t *testing.T) {
	instance := NewCryptoInstance()
	assert.NotNil(t, instance)
}

func createCrypto(t *testing.T) *Crypto {
	dir := io.TestDirectory(t)
	backend, _ := storage.NewFileSystemBackend(dir)
	c := Crypto{
		Storage: backend,
	}
	return &c
}
