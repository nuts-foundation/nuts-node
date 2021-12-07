package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"testing"
)

type mockVaultClient struct {
	// when set, the methods return this error
	err   error
	store map[string]map[string]interface{}
}

func (m mockVaultClient) Read(path string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{
		Data: m.store[path],
	}, nil
}

func (m mockVaultClient) Write(path string, data map[string]interface{}) (*vault.Secret, error) {
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

	t.Run("ok - store and retrieve private key", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		assert.False(t, vaultStorage.PrivateKeyExists(kid), "key should not be in vault")
		assert.NoError(t, vaultStorage.SavePrivateKey(kid, privateKey), "saving should work")
		assert.True(t, vaultStorage.PrivateKeyExists(kid), "key should be in vault")
		result, err := vaultStorage.GetPrivateKey(kid)
		assert.NoError(t, err, "getting key should work")
		assert.Equal(t, privateKey, result, "expected retrieved key to equal original")
	})

	t.Run("error - while writing", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		err := vaultStorage.SavePrivateKey(kid, privateKey)
		assert.Error(t, err, "saving should fail")
		assert.ErrorIs(t, err, vaultError)
	})

	t.Run("error - while reading", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		_, err := vaultStorage.GetPrivateKey(kid)
		assert.Error(t, err, "saving should fail")
		assert.ErrorIs(t, err, vaultError)
	})

	t.Run("ok - keyExists return false in case of vault error", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{err: vaultError}}
		result := vaultStorage.PrivateKeyExists(kid)
		assert.False(t, result, "expected PrivateKeyExists to return false")
	})

	t.Run("error - key not found", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{store: map[string]map[string]interface{}{}}}
		_, err := vaultStorage.GetPrivateKey(kid)
		assert.Error(t, err, "expected error on unknown kid")
		assert.EqualError(t, err, "key not found")
	})

	t.Run("error - pem encoding issues", func(t *testing.T) {
		vaultStorage := vaultKVStorage{client: mockVaultClient{store: map[string]map[string]interface{}{"kv/nuts-private-keys/did:nuts:123#abc": {"key": []byte("foo")}}}}

		t.Run("SavePrivateKey", func(t *testing.T) {
			err := vaultStorage.SavePrivateKey(kid, "123")
			assert.Error(t, err, "expected pem encoding issues on invalid key")
			assert.EqualError(t, err, "unable to convert private key to pem format: x509: unknown key type while marshaling PKCS#8: string")
		})

		t.Run("GetPrivateKey", func(t *testing.T) {
			_, err := vaultStorage.GetPrivateKey(kid)
			assert.Error(t, err, "expected pem encoding issues on invalid key")
			assert.EqualError(t, err, "failed to decode PEM block containing private key")
		})
	})
}
