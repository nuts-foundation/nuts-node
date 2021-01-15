/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/spf13/cobra"

	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/stretchr/testify/assert"
)

func TestCryptoBackend(t *testing.T) {
	t.Run("Instance always returns same instance", func(t *testing.T) {
		client := Instance()
		client2 := Instance()

		if client != client2 {
			t.Error("Expected instances to be the same")
		}
	})
}

func TestCrypto_PublicKey(t *testing.T) {
	client := createCrypto(t)

	publicKey, _ := client.GenerateKeyPair()
	kid, _ := util.Fingerprint(publicKey)

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.GetPublicKey(kid)

		assert.Nil(t, err)
		assert.NotEmpty(t, pub)
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		_, err := client.GetPublicKey("unknown")

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_GetPrivateKey(t *testing.T) {
	client := createCrypto(t)

	t.Run("private key not found", func(t *testing.T) {
		pk, err := client.GetPrivateKey("unknown")
		assert.Nil(t, pk)
		assert.Error(t, err)
	})
	t.Run("get private key, assert non-exportable", func(t *testing.T) {
		publicKey, _ := client.GenerateKeyPair()
		kid, _ := util.Fingerprint(publicKey)

		pk, err := client.GetPrivateKey(kid)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, pk) {
			return
		}
		// Assert that we don't accidentally return the actual RSA/ECDSA key, because they should stay in the storage
		// and be non-exportable.
		_, ok := pk.(*rsa.PrivateKey)
		assert.False(t, ok)
		_, ok = pk.(*ecdsa.PrivateKey)
		assert.False(t, ok)
	})
}

func TestCrypto_KeyExistsFor(t *testing.T) {
	client := createCrypto(t)

	pub, _ := client.GenerateKeyPair()
	kid, _ := util.Fingerprint(pub)

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.PrivateKeyExists(kid))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.PrivateKeyExists("unknown"))
	})
}

func TestCrypto_GenerateKeyPair(t *testing.T) {
	client := createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		publicKey, err := client.GenerateKeyPair()
		assert.NoError(t, err)
		assert.NotNil(t, publicKey)
	})
}

func TestCrypto_doConfigure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := createCrypto(t)
		err := e.doConfigure()
		assert.NoError(t, err)
	})
	t.Run("ok - default = fs backend", func(t *testing.T) {
		client := createCrypto(t)
		err := client.doConfigure()
		if !assert.NoError(t, err) {
			return
		}
		storageType := reflect.TypeOf(client.Storage).String()
		assert.Equal(t, "*storage.fileSystemBackend", storageType)
	})
	t.Run("error - unknown backend", func(t *testing.T) {
		client := createCrypto(t)
		client.Config.Storage = "unknown"
		err := client.doConfigure()
		assert.EqualErrorf(t, err, "only fs backend available for now", "expected error")
	})
}

func TestCrypto_Configure(t *testing.T) {
	createCrypto(t)

	t.Run("ok - configOnce", func(t *testing.T) {
		e := createCrypto(t)
		assert.False(t, e.configDone)
		err := e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
		err = e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
	})
}

func createCrypto(t *testing.T) *Crypto {
	if err := core.NutsConfig().Load(&cobra.Command{}); err != nil {
		panic(err)
	}
	dir := io.TestDirectory(t)
	backend, _ := storage.NewFileSystemBackend(dir)
	crypto := Crypto{
		Storage:    backend,
		Config:     TestCryptoConfig(dir),
	}

	return &crypto
}
