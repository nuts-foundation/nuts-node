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

package storage

import (
	"crypto"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"path/filepath"
)

const privateKeyPathName = "nuts-private-keys"
const defaultPathPrefix = "kv"
const keyName = "key"

// VaultConfig contains the config options to configure the vaultKVStorage backend
type VaultConfig struct {
	// Token to authenticate to the Vault cluster.
	Token string `koanf:"token"`
	// Address of the Vault cluster
	Address string `koanf:"address"`
	// PathPrefix can be used to overwrite the default 'kv' path.
	PathPrefix string `koanf:"pathprefix"`
}

// DefaultVaultConfig returns a VaultConfig with the PathPrefix containing the default value.
func DefaultVaultConfig() VaultConfig {
	return VaultConfig{
		PathPrefix: defaultPathPrefix,
	}
}

// logicaler is an interface which has been implemented by the mockVaultClient and real vault.Logical to allow testing vault without the server.
type logicaler interface {
	Read(path string) (*vault.Secret, error)
	Write(path string, data map[string]interface{}) (*vault.Secret, error)
}

type vaultKVStorage struct {
	config VaultConfig
	client logicaler
}

// NewVaultKVStorage creates a new Vault backend using the kv version 1 secret engine: https://www.vaultproject.io/docs/secrets/kv
// It currently only supports token authentication which should be provided by the token param.
// If config.Address is empty, the VAULT_ADDR environment should be set.
// If config.Token is empty, the VAULT_TOKEN environment should be is set.
func NewVaultKVStorage(config VaultConfig) (Storage, error) {
	client, err := configureVaultClient(config.Token, config.Address)
	if err != nil {
		return nil, err
	}

	vaultStorage := vaultKVStorage{client: client.Logical(), config: config}
	if err = vaultStorage.checkConnection(); err != nil {
		return nil, err
	}
	return vaultStorage, nil
}

func configureVaultClient(token, vaultAddr string) (*vault.Client, error) {
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
	return client, nil
}

func (v vaultKVStorage) checkConnection() error {
	// Perform a token introspection to test the connection. This should be allowed by the default vault token policy.
	secret, err := v.client.Read("auth/token/lookup-self")
	if err != nil {
		return fmt.Errorf("unable to connect to Vault: unable to retrieve token status: %w", err)
	}
	if secret == nil || len(secret.Data) == 0 {
		return fmt.Errorf("could not read token information on auth/token/lookup-self")
	}
	return nil
}

func (v vaultKVStorage) GetPrivateKey(kid string) (crypto.Signer, error) {
	path := privateKeyPath(v.config.PathPrefix, kid)
	value, err := v.getValue(path, keyName)
	if err != nil {
		return nil, err
	}
	privateKey, err := util.PemToPrivateKey([]byte(value))
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (v vaultKVStorage) getValue(path, key string) ([]byte, error) {
	result, err := v.client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key from vault: %w", err)
	}
	rawValue, ok := result.Data[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	value, ok := rawValue.(string)
	if !ok {
		return nil, fmt.Errorf("unable to convert key result to string")
	}
	return []byte(value), nil
}
func (v vaultKVStorage) storeValue(path, key string, value string) error {
	_, err := v.client.Write(path, map[string]interface{}{key: value})
	if err != nil {
		return fmt.Errorf("unable to write private key to vault: %w", err)
	}
	return nil
}

func (v vaultKVStorage) PrivateKeyExists(kid string) bool {
	path := privateKeyPath(v.config.PathPrefix, kid)
	result, err := v.client.Read(path)
	if err != nil {
		return false
	}
	_, ok := result.Data[keyName]
	return ok
}

// privateKeyPath cleans the kid by removing optional slashes and dots and constructs the key path
// This prevents “dot-dot-slash” aka “directory traversal” attacks.
func privateKeyPath(prefix, kid string) string {
	path := fmt.Sprintf("%s/%s/%s", prefix, privateKeyPathName, filepath.Base(kid))
	return filepath.Clean(path)
}

func (v vaultKVStorage) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	path := privateKeyPath(v.config.PathPrefix, kid)
	pem, err := util.PrivateKeyToPem(key)
	if err != nil {
		return fmt.Errorf("unable to convert private key to pem format: %w", err)
	}

	return v.storeValue(path, keyName, pem)
}
