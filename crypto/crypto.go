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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"path"
)

const (
	// ModuleName contains the name of this module
	ModuleName = "Crypto"
)

// Config holds the values for the crypto engine
type Config struct {
	Storage string              `koanf:"crypto.storage"`
	Vault   storage.VaultConfig `koanf:"crypto.vault"`
}

// DefaultCryptoConfig returns a Config with sane defaults
func DefaultCryptoConfig() Config {
	return Config{
		Storage: "fs",
		Vault:   storage.DefaultVaultConfig(),
	}
}

// Crypto holds references to storage and needed config
type Crypto struct {
	Storage storage.Storage
	config  Config
}

// NewCryptoInstance creates a new instance of the crypto engine.
func NewCryptoInstance() *Crypto {
	return &Crypto{
		config: DefaultCryptoConfig(),
	}
}

func (client *Crypto) Name() string {
	return ModuleName
}

func (client *Crypto) Config() interface{} {
	return &client.config
}

func (client *Crypto) setupFSBackend(config core.ServerConfig) error {
	log.Logger().Info("Setting up FileSystem backend for storage of private key material. " +
		"Discouraged for production use unless backups and encryption is properly set up. If not, consider using the Vault backend.")
	fsPath := path.Join(config.Datadir, "crypto")
	var err error
	client.Storage, err = storage.NewFileSystemBackend(fsPath)
	return err
}

func (client *Crypto) setupVaultBackend(_ core.ServerConfig) error {
	log.Logger().Debug("Setting up Vault backend for storage of private key material.")
	var err error
	client.Storage, err = storage.NewVaultKVStorage(client.config.Vault)
	return err
}

// List returns the KIDs of the private keys that are present in the key store.
func (client *Crypto) List() []string {
	return client.Storage.ListPrivateKeys()
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure(config core.ServerConfig) error {
	switch client.config.Storage {
	case "fs":
		return client.setupFSBackend(config)
	case "vaultkv":
		return client.setupVaultBackend(config)
	case "":
		if config.Strictmode {
			return errors.New("backend must be explicitly set in strict mode")
		}
		// default to file system and run this setup again
		return client.setupFSBackend(config)
	default:
		return errors.New("invalid config for crypto.storage. Available options are: vaultkv, fs")
	}
}

// New generates a new key pair.
// Stores the private key, returns the public key
// If a key is overwritten is handled by the storage implementation.
// (it's considered bad practise to reuse a kid for different keys)
func (client *Crypto) New(namingFunc KIDNamingFunc) (Key, error) {
	keyPair, kid, err := generateKeyPairAndKID(namingFunc)
	if err != nil {
		return nil, err
	}
	if err = client.Storage.SavePrivateKey(kid, keyPair); err != nil {
		return nil, fmt.Errorf("could not create new keypair: could not save private key: %w", err)
	}
	return keySelector{
		privateKey: keyPair,
		kid:        kid,
	}, nil
}

func generateKeyPairAndKID(namingFunc KIDNamingFunc) (*ecdsa.PrivateKey, string, error) {
	keyPair, err := generateECKeyPair()
	if err != nil {
		return nil, "", err
	}

	kid, err := namingFunc(keyPair.Public())
	if err != nil {
		return nil, "", err
	}
	log.Logger().
		WithField("keyID", kid).
		Info("Generated new key pair (id=%s)", kid)
	return keyPair, kid, nil
}

func generateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Exists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) Exists(kid string) bool {
	return client.Storage.PrivateKeyExists(kid)
}

func (client *Crypto) Resolve(kid string) (Key, error) {
	keypair, err := client.Storage.GetPrivateKey(kid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrPrivateKeyNotFound
		}
		return nil, err
	}
	return keySelector{
		privateKey: keypair,
		kid:        kid,
	}, nil
}

type keySelector struct {
	privateKey crypto.Signer
	kid        string
}

func (e keySelector) Signer() crypto.Signer {
	return e.privateKey
}

func (e keySelector) KID() string {
	return e.kid
}

func (e keySelector) Public() crypto.PublicKey {
	return e.privateKey.Public()
}
