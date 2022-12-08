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
	"errors"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/stretchr/testify/assert"
)

func TestCrypto_Exists(t *testing.T) {
	client := createCrypto(t)

	kid := "kid"
	client.New(StringNamingFunc(kid))

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.Exists(kid))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.Exists("unknown"))
	})

	t.Run("returns false for invalid kid", func(t *testing.T) {
		assert.False(t, client.Exists("../"))
	})
}

func TestCrypto_New(t *testing.T) {
	client := createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		kid := "kid"
		key, err := client.New(StringNamingFunc(kid))
		assert.NoError(t, err)
		assert.NotNil(t, key.Signer())
		assert.NotNil(t, key.Public())
		assert.Equal(t, kid, key.KID())
	})

	t.Run("error - invalid KID", func(t *testing.T) {
		kid := "../certificate"

		key, err := client.New(StringNamingFunc(kid))

		assert.ErrorContains(t, err, "invalid key ID")
		assert.Nil(t, key)
	})

	t.Run("error - NamingFunction returns err", func(t *testing.T) {
		errorNamingFunc := func(key crypto.PublicKey) (string, error) {
			return "", errors.New("b00m!")
		}
		_, err := client.New(errorNamingFunc)
		assert.Error(t, err)
	})

	t.Run("error - save public key returns an error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		storageMock := storage.NewMockStorage(ctrl)
		storageMock.EXPECT().PrivateKeyExists("123").Return(false)
		storageMock.EXPECT().SavePrivateKey(gomock.Any(), gomock.Any()).Return(errors.New("foo"))

		client := &Crypto{Storage: storageMock}
		key, err := client.New(StringNamingFunc("123"))
		assert.Nil(t, key)
		assert.Error(t, err)
		assert.Equal(t, "could not create new keypair: could not save private key: foo", err.Error())
	})

	t.Run("error - ID already in use", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		storageMock := storage.NewMockStorage(ctrl)
		storageMock.EXPECT().PrivateKeyExists("123").Return(true)

		client := &Crypto{Storage: storageMock}
		key, err := client.New(StringNamingFunc("123"))
		assert.Nil(t, key)
		assert.EqualError(t, err, "key with the given ID already exists", err)
	})
}

func TestCrypto_Resolve(t *testing.T) {
	client := createCrypto(t)
	kid := "kid"
	key, _ := client.New(StringNamingFunc(kid))

	t.Run("ok", func(t *testing.T) {
		resolvedKey, err := client.Resolve("kid")

		require.NoError(t, err)

		assert.Equal(t, key, resolvedKey)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		resolvedKey, err := client.Resolve("../certificate")

		assert.ErrorContains(t, err, "invalid key ID")
		assert.Nil(t, resolvedKey)
	})

	t.Run("error - not found", func(t *testing.T) {
		_, err := client.Resolve("no kidding")

		assert.Equal(t, ErrPrivateKeyNotFound, err)
	})
}

func TestCrypto_Configure(t *testing.T) {
	directory := io.TestDirectory(t)
	cfg := *core.NewServerConfig()
	cfg.Datadir = directory
	t.Run("ok", func(t *testing.T) {
		e := createCrypto(t)
		err := e.Configure(cfg)
		assert.NoError(t, err)
	})
	t.Run("ok - default = fs backend", func(t *testing.T) {
		client := createCrypto(t)
		err := client.Configure(cfg)
		require.NoError(t, err)
		storageType := reflect.TypeOf(client.Storage).String()
		assert.Equal(t, "*storage.fileSystemBackend", storageType)
	})
	t.Run("error - no backend in strict mode is now allowed", func(t *testing.T) {
		client := createCrypto(t)
		cfg := cfg
		cfg.Strictmode = true
		err := client.Configure(cfg)
		assert.EqualError(t, err, "backend must be explicitly set in strict mode", "expected error")
	})
	t.Run("error - unknown backend", func(t *testing.T) {
		client := createCrypto(t)
		client.config.Storage = "unknown"
		err := client.Configure(cfg)
		assert.EqualError(t, err, "invalid config for crypto.storage. Available options are: vaultkv, fs", "expected error")
	})
}

func Test_CryptoGetters(t *testing.T) {
	instance := NewCryptoInstance()
	assert.Equal(t, ModuleName, instance.Name())
	assert.Equal(t, &instance.config, instance.Config())
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

func Test_validateKID(t *testing.T) {
	t.Run("good KIDs", func(t *testing.T) {
		assert.NoError(t, validateKID("admin-token-signing-key"))
		assert.NoError(t, validateKID("did:nuts:2pgo54Z3ytC5EdjBicuJPe5gHyAsjF6rVio1FadSX74j#GxL7A5XNFr_tHcBW_fKCndGGko8DKa2ivPgJAGR0krA"))
		assert.NoError(t, validateKID("did:nuts:3dGjPPeEuHsyNMgJwHkGX3HuJkEEnZ8H19qBqTaqLDbt#JwIR4Vct-EELNKeeB0BZ8Uff_rCZIrOhoiyp5LDFl68"))
		assert.NoError(t, validateKID("did:nuts:BC5MtUzAncmfuGejPFGEgM2k8UfrKZVbbGyFeoG9JEEn#l2swLI0wus8gnzbI3sQaaiE7Yvv2qOUioaIZ8y_JZXs"))
	})
	t.Run("bad KIDs", func(t *testing.T) {
		assert.Error(t, validateKID("../server-certificate"))
		assert.Error(t, validateKID("\\"))
		assert.Error(t, validateKID(""))
		assert.Error(t, validateKID("\t"))
	})
}
