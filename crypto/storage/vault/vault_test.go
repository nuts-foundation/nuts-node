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

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	vault "github.com/hashicorp/vault/api"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockVaultClient struct {
	// when set, the methods return this error
	err   error
	store map[string]map[string]interface{}
}

func (m mockVaultClient) ReadWithContext(_ context.Context, path string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	data, ok := m.store[path]
	if !ok {
		return nil, nil
	}
	return &vault.Secret{
		Data: data,
	}, nil
}

func (m mockVaultClient) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{
		Data: m.store[path],
	}, nil
}

func (m mockVaultClient) WriteWithContext(_ context.Context, path string, data map[string]interface{}) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.store[path] = data
	return &vault.Secret{
		Data: data,
	}, nil
}

func TestVaultKVStorage(t *testing.T) {
	var privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "did:nuts:123#abc"
	var vaultError = errors.New("vault error")
	ctx := context.Background()

	t.Run("ok - store and retrieve private key", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		assert.False(t, vaultStorage.PrivateKeyExists(ctx, kid), "key should not be in vault")
		assert.NoError(t, vaultStorage.SavePrivateKey(ctx, kid, privateKey), "saving should work")
		assert.True(t, vaultStorage.PrivateKeyExists(ctx, kid), "key should be in vault")
		result, err := vaultStorage.GetPrivateKey(ctx, kid)
		assert.NoError(t, err, "getting key should work")
		assert.Equal(t, privateKey, result, "expected retrieved key to equal original")
	})

	t.Run("error - while writing", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		err := vaultStorage.SavePrivateKey(ctx, kid, privateKey)
		assert.Error(t, err, "saving should fail")
		assert.ErrorIs(t, err, vaultError)
	})

	t.Run("error - while reading", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		_, err := vaultStorage.GetPrivateKey(ctx, kid)
		assert.Error(t, err, "saving should fail")
		assert.ErrorIs(t, err, vaultError)
	})

	t.Run("ok - keyExists return false in case of vault error", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		result := vaultStorage.PrivateKeyExists(ctx, kid)
		assert.False(t, result, "expected PrivateKeyExists to return false")
	})

	t.Run("error - key not found (empty response)", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		_, err := vaultStorage.GetPrivateKey(ctx, kid)
		assert.Error(t, err, "expected error on unknown kid")
		assert.EqualError(t, err, "entry not found")

		exists := vaultStorage.PrivateKeyExists(ctx, kid)
		assert.False(t, exists)
	})

	t.Run("error - key not found (key not present in data field)", func(t *testing.T) {
		store := map[string]map[string]interface{}{
			"kv/nuts-private-keys/" + kid: {},
		}
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: store}}
		_, err := vaultStorage.GetPrivateKey(ctx, kid)
		assert.Error(t, err, "expected error on unknown kid")
		assert.EqualError(t, err, "entry not found")

		exists := vaultStorage.PrivateKeyExists(ctx, kid)
		assert.False(t, exists)
	})

	t.Run("error - encoding issues", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{"kv/nuts-private-keys/did:nuts:123#abc": {"key": []byte("foo")}}}}

		t.Run("SavePrivateKey", func(t *testing.T) {
			err := vaultStorage.SavePrivateKey(ctx, kid, "123")
			assert.Error(t, err, "expected pem encoding issues on invalid key")
			assert.EqualError(t, err, "unable to convert private key to pem format: x509: unknown key type while marshaling PKCS#8: string")
		})

		t.Run("GetPrivateKey", func(t *testing.T) {
			_, err := vaultStorage.GetPrivateKey(ctx, kid)
			assert.Error(t, err, "expected type conversion error on byte array")
			assert.EqualError(t, err, "unable to convert key result to string")
		})
	})
}

func TestVaultKVStorage_CheckHealth(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{"auth/token/lookup-self": {"key": []byte("foo")}}}}
		result := vaultStorage.CheckHealth()

		assert.Equal(t, core.HealthStatusUp, result[StorageType].Status)
		assert.Empty(t, result[StorageType].Details)
	})

	t.Run("error - lookup token endpoint returns empty response", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		result := vaultStorage.CheckHealth()

		assert.Equal(t, core.HealthStatusDown, result[StorageType].Status)
		assert.Equal(t, "could not read token information on auth/token/lookup-self", result[StorageType].Details)
	})
}

func TestVaultKVStorage_ListPrivateKeys(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("{\"request_id\":\"d728876e-ea1e-8a58-f297-dcd4cd0a41bb\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"keys\":[\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#45KSfeG71ZMh9NjGzSWFfcMsmu5587J93prf8Io1wf4\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#6Cc91cQQze7txdcEor_zkM4YSwX0kH1wsiMyeV9nedA\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#MaNou-G07aPD7oheretmI2C_VElG1XaHiqh89SlfkWQ\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#alt3OIpy21VxDlWao0jRumIyXi3qHBPG-ir5q8zdv8w\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#wumme98rwUOQVle-sT_MP3pRg_oqblvlanv3zYR2scc\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#yBLHNjVq_WM3qzsRQ_zi2yOcedjY9FfVfByp3HgEbR8\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#yREqK5id7I6SP1Iq7teThin2o53w17tb9sgEXZBIcDo\"]},\"wrap_info\":null,\"warnings\":null,\"auth\":null}"))
	}))
	defer s.Close()
	storage, _ := NewVaultKVStorage(Config{Address: s.URL})
	keys := storage.ListPrivateKeys(context.Background())
	assert.Len(t, keys, 7)
	// Assert first and last entry, rest should be OK then
	assert.Equal(t, "did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#45KSfeG71ZMh9NjGzSWFfcMsmu5587J93prf8Io1wf4", keys[0])
	assert.Equal(t, "did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#yREqK5id7I6SP1Iq7teThin2o53w17tb9sgEXZBIcDo", keys[6])
}

func Test_PrivateKeyPath(t *testing.T) {
	t.Run("it removes dot-dot-slash paths from the kid", func(t *testing.T) {
		assert.Equal(t, "kv/nuts-private-keys/did:nuts:123#abc", privateKeyPath("kv", "did:nuts:123#abc"))
		assert.Equal(t, "kv/nuts-private-keys/did:nuts:123#abc", privateKeyPath("kv", "../did:nuts:123#abc"))
		assert.Equal(t, "kv/nuts-private-keys/did:nuts:123#abc", privateKeyPath("kv", "/../did:nuts:123#abc"))
	})
}

func TestVaultKVStorage_configure(t *testing.T) {
	t.Run("ok - configure a new vault store", func(t *testing.T) {
		_, err := configureVaultClient(Config{
			Token:   "tokenString",
			Address: "http://localhost:123",
		})
		assert.NoError(t, err)
	})

	t.Run("error - invalid address", func(t *testing.T) {
		_, err := configureVaultClient(Config{
			Token:   "tokenString",
			Address: "%zzzzz",
		})
		assert.Error(t, err)
		assert.EqualError(t, err, "vault address invalid: failed to set address: parse \"%zzzzz\": invalid URL escape \"%zz\"")
	})
	t.Run("VAULT_TOKEN not overriden by empty config", func(t *testing.T) {
		t.Setenv("VAULT_TOKEN", "123")

		client, err := configureVaultClient(Config{
			Address: "http://localhost:123",
		})

		require.NoError(t, err)
		assert.Equal(t, "123", client.Token())
	})
}

func TestNewVaultKVStorage(t *testing.T) {
	t.Run("ok - data", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("{\"data\": {\"keys\":[]}}"))
		}))
		defer s.Close()
		storage, err := NewVaultKVStorage(Config{Address: s.URL})
		assert.NoError(t, err)
		assert.NotNil(t, storage)
	})

	t.Run("error - vault StatusUnauthorized", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusUnauthorized)
		}))
		defer s.Close()
		storage, err := NewVaultKVStorage(Config{Address: s.URL})
		assert.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "unable to connect to Vault: unable to retrieve token status: Error making API request"))
		assert.Nil(t, storage)
	})

	t.Run("error - wrong URL", func(t *testing.T) {
		storage, err := NewVaultKVStorage(Config{Address: "http://non-existing"})
		require.Error(t, err)
		assert.Regexp(t, `no such host|Temporary failure in name resolution`, err.Error())
		assert.Nil(t, storage)
	})
}

func TestVaultKVStorage_checkConnection(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{"auth/token/lookup-self": {"key": []byte("foo")}}}}
		err := vaultStorage.checkConnection()
		assert.NoError(t, err)
	})

	t.Run("error - lookup token endpoint empty", func(t *testing.T) {
		vaultStorage := vaultKVStorage{config: DefaultConfig(), client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		err := vaultStorage.checkConnection()
		assert.EqualError(t, err, "could not read token information on auth/token/lookup-self")
	})

	t.Run("error - vault error while reading", func(t *testing.T) {
		var vaultError = errors.New("vault error")
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		err := vaultStorage.checkConnection()
		assert.EqualError(t, err, "unable to connect to Vault: unable to retrieve token status: vault error")
	})
}
