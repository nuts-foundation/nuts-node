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
	"context"
	"crypto"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
)

func TestCrypto_Exists(t *testing.T) {
	ctx := context.Background()
	client := createCrypto(t)

	kid := "kid"
	client.New(audit.TestContext(), ECP256Key, StringNamingFunc(kid))

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.Exists(ctx, kid))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.Exists(ctx, "unknown"))
	})

	t.Run("returns false for invalid kid", func(t *testing.T) {
		assert.False(t, client.Exists(ctx, "../"))
	})
}

func TestCrypto_New(t *testing.T) {
	client := createCrypto(t)
	logrus.StandardLogger().SetFormatter(&logrus.JSONFormatter{})
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		kid := "kid"
		auditLogs := audit.CaptureLogs(t)

		key, err := client.New(ctx, ECP256Key, StringNamingFunc(kid))

		assert.NoError(t, err)
		assert.NotNil(t, key.Public())
		assert.Equal(t, kid, key.KID())
		auditLogs.AssertContains(t, ModuleName, "CreateNewKey", audit.TestActor, "Generating new key pair: kid")
	})

	t.Run("error - invalid KID", func(t *testing.T) {
		kid := "../certificate"

		key, err := client.New(ctx, ECP256Key, StringNamingFunc(kid))

		assert.ErrorContains(t, err, "invalid key ID")
		assert.Nil(t, key)
	})

	t.Run("error - NamingFunction returns err", func(t *testing.T) {
		errorNamingFunc := func(key crypto.PublicKey) (string, error) {
			return "", errors.New("b00m!")
		}
		_, err := client.New(ctx, ECP256Key, errorNamingFunc)
		assert.Error(t, err)
	})

	t.Run("error - save public key returns an error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		storageMock := spi.NewMockStorage(ctrl)
		storageMock.EXPECT().PrivateKeyExists(ctx, "123").Return(false)
		storageMock.EXPECT().SavePrivateKey(ctx, gomock.Any(), gomock.Any()).Return(errors.New("foo"))

		client := &Crypto{storage: storageMock}
		key, err := client.New(ctx, ECP256Key, StringNamingFunc("123"))
		assert.Nil(t, key)
		assert.Error(t, err)
		assert.Equal(t, "could not create new keypair: could not save private key: foo", err.Error())
	})

	t.Run("error - ID already in use", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		storageMock := spi.NewMockStorage(ctrl)
		storageMock.EXPECT().PrivateKeyExists(ctx, "123").Return(true)

		client := &Crypto{storage: storageMock}
		key, err := client.New(ctx, ECP256Key, StringNamingFunc("123"))
		assert.Nil(t, key)
		assert.EqualError(t, err, "key with the given ID already exists", err)
	})
}

func TestCrypto_Resolve(t *testing.T) {
	ctx := context.Background()
	client := createCrypto(t)
	kid := "kid"
	key, _ := client.New(audit.TestContext(), ECP256Key, StringNamingFunc(kid))

	t.Run("ok", func(t *testing.T) {
		resolvedKey, err := client.Resolve(ctx, "kid")

		require.NoError(t, err)

		assert.Equal(t, key, resolvedKey)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		resolvedKey, err := client.Resolve(ctx, "../certificate")

		assert.ErrorContains(t, err, "invalid key ID")
		assert.Nil(t, resolvedKey)
	})

	t.Run("error - not found", func(t *testing.T) {
		_, err := client.Resolve(ctx, "no kidding")

		assert.Equal(t, ErrPrivateKeyNotFound, err)
	})
}

func TestCrypto_setupBackend(t *testing.T) {
	directory := io.TestDirectory(t)
	cfg := *core.NewServerConfig()
	cfg.Datadir = directory

	t.Run("backends should be wrapped", func(t *testing.T) {

		t.Run("ok - fs backend is wrapped", func(t *testing.T) {
			client := createCrypto(t)
			err := client.setupFSBackend(cfg)
			require.NoError(t, err)
			storageType := reflect.TypeOf(client.storage).String()
			assert.Equal(t, "spi.wrapper", storageType)
		})

		t.Run("ok - vault backend is wrapped", func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = writer.Write([]byte("{\"data\": {\"keys\":[]}}"))
			}))

			defer s.Close()
			client := createCrypto(t)
			client.config.Vault.Address = s.URL
			err := client.setupVaultBackend(cfg)
			require.NoError(t, err)
			storageType := reflect.TypeOf(client.storage).String()
			assert.Equal(t, "spi.wrapper", storageType)
		})
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
		assert.EqualError(t, err, "invalid config for crypto.storage. Available options are: vaultkv, fs, external(experimental)", "expected error")
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
	backend, _ := fs.NewFileSystemBackend(dir)
	c := Crypto{
		storage: spi.NewValidatedKIDBackendWrapper(backend, kidPattern),
	}
	return &c
}
