package storage

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/nuts-foundation/nuts-node/crypto/util"
)

const privateKeyPath = "nuts-private-keys"
const publicKeyPath = "nuts-public-keys"
const kvEnginePath = "kv"
const keyName = "key"

type vaultKVStorage struct {
	client *vault.Client
}

func NewVaultKVStorage(token string) (Storage, error) {
	config := vault.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	client.SetToken(token)

	_, err = client.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return nil, fmt.Errorf("unable to connect to vault: unable to retrieve token status: %w", err)
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

func (v vaultKVStorage) GetPublicKey(kid string) (PublicKeyEntry, error) {
	path := fmt.Sprintf("%s/%s/%s", kvEnginePath, publicKeyPath, kid)
	publicKeyEntry := PublicKeyEntry{}
	value, err := v.getValue(path, keyName)
	if err != nil {
		return publicKeyEntry, fmt.Errorf("unable to retrieve public key from vault: %w", err)
	}
	jsonKey, err := base64.RawStdEncoding.DecodeString(string(value))
	if err != nil {
		return publicKeyEntry, fmt.Errorf("unable to base64 decode the key: %w", err)
	}

	err = json.Unmarshal(jsonKey, &publicKeyEntry)
	return publicKeyEntry, err
}

func (v vaultKVStorage) SavePublicKey(kid string, key PublicKeyEntry) error {
	path := fmt.Sprintf("%s/%s/%s", kvEnginePath, publicKeyPath, kid)
	jsonKey, err := json.Marshal(key)
	if err != nil {
		return err
	}

	encodedKey := base64.RawStdEncoding.EncodeToString(jsonKey)
	return v.storeValue(path, keyName, []byte(encodedKey))
}
