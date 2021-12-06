package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"testing"
)

type mockVaultClient struct {
	store map[string]map[string]interface{}
}

func (m mockVaultClient) Read(path string) (*vault.Secret, error) {
	return &vault.Secret{
		Data: m.store[path],
	}, nil
}

func (m mockVaultClient) Write(path string, data map[string]interface{}) (*vault.Secret, error) {
	m.store[path] = data
	return &vault.Secret{
		Data: data,
	}, nil
}

func TestVaultKVStorage(t *testing.T) {
	t.Run("ok - store and retrieve private key", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		const kid = "did:nuts:123#abc"
		assert.False(t, vaultStorage.PrivateKeyExists(kid))
		var privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NoError(t, vaultStorage.SavePrivateKey(kid, privateKey))
		assert.True(t, vaultStorage.PrivateKeyExists(kid))

		result, err := vaultStorage.GetPrivateKey(kid)
		assert.NoError(t, err)
		assert.Equal(t, privateKey, result)
	})
}
