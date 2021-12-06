package storage

import (
	"crypto"
	"encoding/base64"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/nuts-foundation/nuts-node/crypto/util"
)

const privateKeyPath = "nuts-private-keys"
const kvEnginePath = "kv"
const keyName = "key"

type vaultKVStorage struct {
	client *vault.Client
}

// NewVaultKVStorage creates a new Vault backend using the kv version 1 secret engine: https://www.vaultproject.io/docs/secrets/kv
// It currently only supports token authentication which should be provided by the token param.
// If vaultAddr is empty, the VAULT_ADDR environment should be set.
// If token is empty, the VAULT_TOKEN environment should be is set.
func NewVaultKVStorage(token string, vaultAddr string) (Storage, error) {
	config := vault.DefaultConfig()
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	client.SetToken(token)
	if vaultAddr != "" {
		if err = client.SetAddress(vaultAddr); err != nil {
			return nil, fmt.Errorf("vault address invalid: %w", err)
		}
	}

	_, err = client.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return nil, fmt.Errorf("unable to connect to Vault: unable to retrieve token status: %w", err)
	}

	return vaultKVStorage{client: client}, nil

}

func (v vaultKVStorage) GetPrivateKey(kid string) (crypto.Signer, error) {
	path := fmt.Sprintf("%s/%s/%s", kvEnginePath, privateKeyPath, kid)
	value, err := v.getValue(path, keyName)
	privateKey, err := util.PemToPrivateKey(value)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (v vaultKVStorage) getValue(path, key string) ([]byte, error) {
	result, err := v.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key from vault: %w", err)
	}
	rawValue, ok := result.Data[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	value, ok := rawValue.([]byte)
	if !ok {
		return nil, fmt.Errorf("unable to convert key result to bytes")
	}
	return value, nil
}
func (v vaultKVStorage) storeValue(path, key string, value []byte) error {
	_, err := v.client.Logical().Write(path, map[string]interface{}{key: value})
	if err != nil {
		return fmt.Errorf("unable to write private key to vault: %w", err)
	}
	return nil
}

func (v vaultKVStorage) PrivateKeyExists(kid string) bool {
	path := fmt.Sprintf("%s/%s/%s", kvEnginePath, privateKeyPath, kid)
	result, err := v.client.Logical().Read(path)
	if err != nil {
		return false
	}
	_, ok := result.Data[keyName]
	return ok
}

func (v vaultKVStorage) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	path := fmt.Sprintf("%s/%s/%s", kvEnginePath, privateKeyPath, kid)
	pem, err := util.PrivateKeyToPem(key)
	if err != nil {
		return fmt.Errorf("unable to convert private key to pem format: %w", err)
	}

	encodedKey := base64.RawStdEncoding.EncodeToString([]byte(pem))
	return v.storeValue(path, keyName, []byte(encodedKey))
}
