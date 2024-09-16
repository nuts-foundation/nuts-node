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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
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
	_, _ = newKeyReference(t, client, kid)

	t.Run("returns true for existing key", func(t *testing.T) {
		exists, err := client.Exists(ctx, kid)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		exists, err := client.Exists(ctx, "unknown")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestCrypto_Migrate(t *testing.T) {
	backend := NewMemoryStorage()
	db := orm.NewTestDatabase(t)
	client := &Crypto{backend: backend, db: db}

	t.Run("ok - 1 key migrated", func(t *testing.T) {
		keypair, _ := spi.GenerateKeyPair()
		err := backend.SavePrivateKey(context.Background(), "test", keypair)
		require.NoError(t, err)

		err = client.Migrate()
		require.NoError(t, err)

		keys := client.List(context.Background())
		require.Len(t, keys, 1)
		// kid will equal the key name
		assert.Equal(t, "test", keys[0])

		t.Run("ok - already exists", func(t *testing.T) {
			err = client.Migrate()
			assert.NoError(t, err)
		})
	})
}

func TestCrypto_New(t *testing.T) {
	client := createCrypto(t)
	logrus.StandardLogger().SetFormatter(&logrus.JSONFormatter{})
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		auditLogs := audit.CaptureAuditLogs(t)

		ref, pubKey, err := client.New(ctx, StringNamingFunc("kid"))

		assert.NoError(t, err)
		assert.NotNil(t, ref)
		assert.NotNil(t, pubKey)
		auditLogs.AssertContains(t, ModuleName, "CreateNewKey", audit.TestActor, "Generated new key pair: "+ref.KID)
	})
	t.Run("error - invalid naming function", func(t *testing.T) {
		_, _, err := client.New(ctx, ErrorNamingFunc(assert.AnError))

		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
	})
	t.Run("error from backend", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		storageMock := spi.NewMockStorage(ctrl)
		storageMock.EXPECT().NewPrivateKey(ctx, gomock.Any()).Return(nil, "", assert.AnError)
		client := createCrypto(t)
		client.backend = storageMock

		_, _, err := client.New(ctx, StringNamingFunc("kid"))

		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
	})
}

func TestCrypto_Delete(t *testing.T) {
	ctx := audit.TestContext()
	auditLogs := audit.CaptureAuditLogs(t)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		storageMock := spi.NewMockStorage(ctrl)
		storageMock.EXPECT().DeletePrivateKey(ctx, "test").Return(nil)
		client := &Crypto{backend: storageMock, db: orm.NewTestDatabase(t)}
		err := client.db.Save(&orm.KeyReference{KID: "kid", KeyName: "test", Version: "1"}).Error
		require.NoError(t, err)

		err = client.Delete(ctx, "kid")

		assert.NoError(t, err)
		auditLogs.AssertContains(t, ModuleName, "DeleteKey", audit.TestActor, "Deleting private key: kid")
	})
}

func TestCrypto_Resolve(t *testing.T) {
	ctx := context.Background()
	client := createCrypto(t)
	kid := "kid"
	_, pubKey := newKeyReference(t, client, kid)

	t.Run("ok", func(t *testing.T) {
		resolvedKey, err := client.Resolve(ctx, "kid")

		require.NoError(t, err)

		assert.Equal(t, pubKey, resolvedKey)
	})
	t.Run("error - not found", func(t *testing.T) {
		_, err := client.Resolve(ctx, "no kidding")

		assert.Equal(t, ErrPrivateKeyNotFound, err)
	})
	t.Run("key not found in backend", func(t *testing.T) {
		keyRef := orm.KeyReference{
			KID:     "known",
			KeyName: "unknown",
			Version: "1",
		}
		err := client.db.Save(&keyRef).Error
		require.NoError(t, err)

		_, err = client.Resolve(ctx, "unknown")

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
			storageType := reflect.TypeOf(client.backend).String()
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
			storageType := reflect.TypeOf(client.backend).String()
			assert.Equal(t, "spi.wrapper", storageType)
		})
	})
}

func TestCrypto_Configure(t *testing.T) {
	directory := io.TestDirectory(t)
	cfg := core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = directory
	})
	t.Run("default backend (fs) can be used in non-strictmode", func(t *testing.T) {
		e := createCrypto(t)
		cfg := cfg
		cfg.Strictmode = false
		err := e.Configure(cfg)
		assert.NoError(t, err)
	})
	t.Run("error - no backend in strict mode is now allowed", func(t *testing.T) {
		client := createCrypto(t)
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
	instance := NewCryptoInstance(nil)
	assert.Equal(t, ModuleName, instance.Name())
	assert.Equal(t, &instance.config, instance.Config())
}

func TestNewCryptoInstance(t *testing.T) {
	instance := NewCryptoInstance(nil)
	assert.NotNil(t, instance)
	assert.Empty(t, instance.config.Storage)
}

func createCrypto(t *testing.T) *Crypto {
	dir := io.TestDirectory(t)
	backend, _ := fs.NewFileSystemBackend(dir)
	c := Crypto{
		backend: spi.NewValidatedKIDBackendWrapper(backend, spi.KidPattern),
		storage: storage.NewTestStorageEngine(t),
		db:      orm.NewTestDatabase(t),
	}
	return &c
}
