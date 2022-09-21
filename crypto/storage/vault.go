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
	"errors"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"path/filepath"
	"time"
)

const privateKeyPathName = "nuts-private-keys"
const defaultPathPrefix = "kv"
const keyName = "key"

var errKeyNotFound = errors.New("key not found")

// VaultConfig contains the config options to configure the vaultKVStorage backend
type VaultConfig struct {
	// Token to authenticate to the Vault cluster.
	Token string `koanf:"token"`
	// Address of the Vault cluster
	Address string `koanf:"address"`
	// PathPrefix can be used to overwrite the default 'kv' path.
	PathPrefix string `koanf:"pathprefix"`
	// Timeout specifies the Vault client timeout.
	Timeout time.Duration
}

// DefaultVaultConfig returns a VaultConfig with the PathPrefix containing the default value.
func DefaultVaultConfig() VaultConfig {
	return VaultConfig{
		PathPrefix: defaultPathPrefix,
		Timeout:    5 * time.Second,
	}
}

// logicaler is an interface which has been implemented by the mockVaultClient and real vault.Logical to allow testing vault without the server.
type logicaler interface {
	Read(path string) (*vault.Secret, error)
	Write(path string, data map[string]interface{}) (*vault.Secret, error)
	ReadWithData(path string, data map[string][]string) (*vault.Secret, error)
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
	client, err := configureVaultClient(config)
	if err != nil {
		return nil, err
	}

	vaultStorage := vaultKVStorage{client: client.Logical(), config: config}
	if err = vaultStorage.checkConnection(); err != nil {
		return nil, err
	}
	return vaultStorage, nil
}

func configureVaultClient(cfg VaultConfig) (*vault.Client, error) {
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Timeout = cfg.Timeout
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	// The Vault client will automatically use the env var VAULT_TOKEN
	// the client.SetToken overrides this value, so only set when not empty
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}
	if cfg.Address != "" {
		if err = client.SetAddress(cfg.Address); err != nil {
			return nil, fmt.Errorf("vault address invalid: %w", err)
		}
	}
	return client, nil
}

func (v vaultKVStorage) checkConnection() error {
	// Perform a token introspection to test the connection. This should be allowed by the default vault token policy.
	log.Logger().Debug("Verifying Vault connection...")
	secret, err := v.client.Read("auth/token/lookup-self")
	if err != nil {
		return fmt.Errorf("unable to connect to Vault: unable to retrieve token status: %w", err)
	}
	if secret == nil || len(secret.Data) == 0 {
		return fmt.Errorf("could not read token information on auth/token/lookup-self")
	}
	log.Logger().Info("Connected to Vault.")
	return nil
}

func (v vaultKVStorage) GetPrivateKey(kid string) (crypto.Signer, error) {
	path := privateKeyPath(v.config.PathPrefix, kid)
	value, err := v.getValue(path, keyName)
	if err != nil {
		return nil, err
	}
	privateKey, err := util.PemToPrivateKey(value)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (v vaultKVStorage) getValue(path, key string) ([]byte, error) {
	result, err := v.client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read key from vault: %w", err)
	}
	if result == nil || result.Data == nil {
		return nil, errKeyNotFound
	}
	rawValue, ok := result.Data[key]
	if !ok {
		return nil, errKeyNotFound
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
	_, err := v.getValue(path, keyName)
	return err == nil
}

func (v vaultKVStorage) ListPrivateKeys() []string {
	path := privateKeyListPath(v.config.PathPrefix)
	response, err := v.client.ReadWithData(path, map[string][]string{"list": {"true"}})
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Could not list private keys in Vault")
		return nil
	}
	if response == nil {
		log.Logger().Warnf("Vault returned nothing while fetching private keys, maybe the path prefix ('%s') is incorrect or the engine doesn't exist?", v.config.PathPrefix)
		return nil
	}
	keys, _ := response.Data["keys"].([]interface{})
	var result []string
	for _, key := range keys {
		keyStr, ok := key.(string)
		if ok {
			result = append(result, keyStr)
		}
	}
	return result
}

// privateKeyPath cleans the kid by removing optional slashes and dots and constructs the key path
// This prevents “dot-dot-slash” aka “directory traversal” attacks.
func privateKeyPath(prefix, kid string) string {
	path := fmt.Sprintf("%s/%s/%s", prefix, privateKeyPathName, filepath.Base(kid))
	return filepath.Clean(path)
}

func privateKeyListPath(prefix string) string {
	path := fmt.Sprintf("%s/%s", prefix, privateKeyPathName)
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
