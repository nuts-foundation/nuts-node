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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"path"
	"regexp"
	"time"

	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/storage/external"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/storage/vault"
)

const (
	// ModuleName contains the name of this module
	ModuleName = "Crypto"
)

var kidPattern = regexp.MustCompile(`^[\da-zA-Z_\- :#.]+$`)

// Config holds the values for the crypto engine
type Config struct {
	Storage  string          `koanf:"storage"`
	Vault    vault.Config    `koanf:"vault"`
	External external.Config `koanf:"external"`
}

// DefaultCryptoConfig returns a Config with a fs backend storage
func DefaultCryptoConfig() Config {
	return Config{
		Storage: fs.StorageType,
		Vault:   vault.DefaultConfig(),
		External: external.Config{
			Timeout: 100 * time.Millisecond,
		},
	}
}

// Crypto holds references to storage and needed config
type Crypto struct {
	storage spi.Storage
	config  Config
}

func (client *Crypto) CheckHealth() map[string]core.Health {
	return client.storage.CheckHealth()
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
		"Discouraged for production use unless backups and encryption is properly set up. Consider using the Hashicorp Vault backend.")
	fsPath := path.Join(config.Datadir, "crypto")
	var err error
	fsBackend, err := fs.NewFileSystemBackend(fsPath)
	if err != nil {
		return err
	}
	client.storage = spi.NewValidatedKIDBackendWrapper(fsBackend, kidPattern)
	return nil
}

func (client *Crypto) setupStorageAPIBackend() error {
	log.Logger().Debug("Setting up StorageAPI backend for storage of private key material.")
	apiBackend, err := external.NewAPIClient(client.config.External)
	if err != nil {
		return fmt.Errorf("unable to set up external crypto API client: %w", err)
	}
	client.storage = spi.NewValidatedKIDBackendWrapper(apiBackend, kidPattern)
	return nil
}

func (client *Crypto) setupVaultBackend(_ core.ServerConfig) error {
	log.Logger().Debug("Setting up Vault backend for storage of private key material. " +
		"This feature is experimental and may change in the future.")
	var err error
	vaultBackend, err := vault.NewVaultKVStorage(client.config.Vault)
	if err != nil {
		return err
	}

	client.storage = spi.NewValidatedKIDBackendWrapper(vaultBackend, kidPattern)
	return nil
}

// List returns the KIDs of the private keys that are present in the key store.
func (client *Crypto) List(ctx context.Context) []string {
	return client.storage.ListPrivateKeys(ctx)
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure(config core.ServerConfig) error {
	switch client.config.Storage {
	case fs.StorageType:
		return client.setupFSBackend(config)
	case vault.StorageType:
		return client.setupVaultBackend(config)
	case external.StorageType:
		return client.setupStorageAPIBackend()
	case "":
		if config.Strictmode {
			return errors.New("backend must be explicitly set in strict mode")
		}
		// default to file system and run this setup again
		return client.setupFSBackend(config)
	default:
		return fmt.Errorf("invalid config for crypto.storage. Available options are: vaultkv, fs, %s(experimental)", external.StorageType)
	}
}

// New generates a new key pair.
// Stores the private key, returns the public basicKey.
// It returns an error when a key with the resulting ID already exists.
func (client *Crypto) New(ctx context.Context, keyType KeyType, namingFunc KIDNamingFunc) (Key, error) {
	switch keyType {
	case ECP256Key, ECP256k1Key, Ed25519Key, RSA2048Key, RSA3072Key, RSA4096Key:
		// ok
	default:
		return nil, fmt.Errorf("invalid key type: %s", keyType)
	}

	keyPair, kid, err := generateKeyPairAndKID(namingFunc)
	if err != nil {
		return nil, err
	}

	audit.Log(ctx, log.Logger(), audit.CryptoNewKeyEvent).Infof("Generating new key pair: %s", kid)
	if client.storage.PrivateKeyExists(ctx, kid) {
		return nil, errors.New("key with the given ID already exists")
	}
	if err = client.storage.SavePrivateKey(ctx, kid, keyPair); err != nil {
		return nil, fmt.Errorf("could not create new keypair: could not save private key: %w", err)
	}
	return basicKey{
		publicKey: keyPair.Public(),
		kid:       kid,
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
		WithField(core.LogFieldKeyID, kid).
		Debug("Generated new key pair")
	return keyPair, kid, nil
}

func generateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Exists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) Exists(ctx context.Context, kid string) bool {
	return client.storage.PrivateKeyExists(ctx, kid)
}

func (client *Crypto) Resolve(ctx context.Context, kid string) (Key, error) {
	keypair, err := client.storage.GetPrivateKey(ctx, kid)
	if err != nil {
		if errors.Is(err, spi.ErrNotFound) {
			return nil, ErrPrivateKeyNotFound
		}
		return nil, err
	}
	return basicKey{
		publicKey: keypair.Public(),
		kid:       kid,
	}, nil
}

// memoryKey is a Key that is only present in memory and not stored in the key store.
type memoryKey struct {
	basicKey
	privateKey crypto.Signer
}

func (m memoryKey) Signer() crypto.Signer {
	return m.privateKey
}

type basicKey struct {
	publicKey crypto.PublicKey
	kid       string
}

func (e basicKey) KID() string {
	return e.kid
}

func (e basicKey) Public() crypto.PublicKey {
	return e.publicKey
}
