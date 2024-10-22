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
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/crypto/storage/azure"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"gorm.io/gorm"
	"path"
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

// Config holds the values for the crypto engine
type Config struct {
	Storage       string          `koanf:"storage"`
	Vault         vault.Config    `koanf:"vault"`
	AzureKeyVault azure.Config    `koanf:"azurekv"`
	External      external.Config `koanf:"external"`
}

// DefaultCryptoConfig returns a Config with default settings for Vault and Azure keyVault
func DefaultCryptoConfig() Config {
	return Config{
		Vault:         vault.DefaultConfig(),
		AzureKeyVault: azure.DefaultConfig(),
		External: external.Config{
			Timeout: 100 * time.Millisecond,
		},
	}
}

var _ KeyStore = (*Crypto)(nil)

// Crypto holds references to storage and needed config
type Crypto struct {
	config  Config
	backend spi.Storage
	db      *gorm.DB
	storage storage.Engine
}

func (client *Crypto) CheckHealth() map[string]core.Health {
	return client.backend.CheckHealth()
}

// NewCryptoInstance creates a new instance of the crypto engine.
func NewCryptoInstance(storage storage.Engine) *Crypto {
	return &Crypto{
		config:  DefaultCryptoConfig(),
		storage: storage,
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
	fsBackend, err := fs.NewFileSystemBackend(fsPath)
	if err != nil {
		return err
	}
	client.backend = spi.NewValidatedKIDBackendWrapper(fsBackend, spi.KidPattern)
	return nil
}

func (client *Crypto) setupStorageAPIBackend() error {
	log.Logger().Debug("Setting up StorageAPI backend for storage of private key material.")
	log.Logger().Warn("External key storage backend is deprecated and will be removed in the future.")
	apiBackend, err := external.NewAPIClient(client.config.External)
	if err != nil {
		return fmt.Errorf("unable to set up external crypto API client: %w", err)
	}
	client.backend = spi.NewValidatedKIDBackendWrapper(apiBackend, spi.KidPattern)
	return nil
}

func (client *Crypto) setupVaultBackend(_ core.ServerConfig) error {
	log.Logger().Debug("Setting up Vault backend for storage of private key material. " +
		"This feature is experimental and may change in the future.")
	vaultBackend, err := vault.NewVaultKVStorage(client.config.Vault)
	if err != nil {
		return err
	}

	client.backend = spi.NewValidatedKIDBackendWrapper(vaultBackend, spi.KidPattern)
	return nil
}

func (client *Crypto) setupAzureKeyVaultBackend(_ core.ServerConfig) error {
	log.Logger().Debug("Setting up Azure Key Vault backend for storage of private key material.")
	azureBackend, err := azure.New(client.config.AzureKeyVault)
	if err != nil {
		return err
	}
	client.backend = spi.NewValidatedKIDBackendWrapper(azureBackend, spi.KidPattern)
	return nil
}

// List returns the KIDs of the private keys that are present in the key store.
func (client *Crypto) List(ctx context.Context) []string {
	kids := make([]string, 0)
	err := client.continueTransaction(ctx, func(tx *gorm.DB) error {
		keyRefs := make([]orm.KeyReference, 0)
		if err := tx.WithContext(ctx).Find(&keyRefs).Error; err != nil {
			return err
		}
		for _, keyRef := range keyRefs {
			kids = append(kids, keyRef.KID)
		}
		return nil
	})
	if err != nil {
		log.Logger().Errorf("could not list keys: %s", err.Error())
	}

	return kids
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure(config core.ServerConfig) error {
	client.db = client.storage.GetSQLDatabase()

	switch client.config.Storage {
	case fs.StorageType:
		return client.setupFSBackend(config)
	case vault.StorageType:
		return client.setupVaultBackend(config)
	case azure.StorageType:
		return client.setupAzureKeyVaultBackend(config)
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

func (client *Crypto) Migrate() error {
	// List all keys from the backend
	// check for each key if a KeyReference exists in the SQL database
	// if not, create a new KeyReference
	// else do nothing

	outerContext := context.TODO()

	// run everything in a single transaction
	// we do not expect to have a lot of keys, so this should be fine
	return client.db.Transaction(func(tx *gorm.DB) error {
		ctx := context.WithValue(outerContext, storage.TransactionKey{}, tx)
		keys := client.backend.ListPrivateKeys(ctx)
		for _, keyNameVersion := range keys {
			var keyRef orm.KeyReference
			// find existing record, if it exists do nothing
			err := tx.WithContext(ctx).Model(&orm.KeyReference{}).Where("key_name = ? and version = ?", keyNameVersion.KeyName, keyNameVersion.Version).First(&keyRef).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					// create a new key reference
					ref := &orm.KeyReference{
						KID:     keyNameVersion.KeyName,
						KeyName: keyNameVersion.KeyName,
						Version: keyNameVersion.Version,
					}
					err := tx.Save(ref).Error
					if err != nil {
						log.Logger().Errorf("could not save key reference to database: %s", err.Error())
					}
				} else {
					return fmt.Errorf("error finding KeyReference in DB: %w", err)
				}
			}
		}
		return nil
	})
}

// New generates a new key pair.
// Stores the private key, returns the public key and DB reference.
// It returns an error when a key with the resulting ID already exists.
func (client *Crypto) New(ctx context.Context, namingFunc KIDNamingFunc) (*orm.KeyReference, crypto.PublicKey, error) {
	var ref *orm.KeyReference
	var publicKey crypto.PublicKey
	err := client.continueTransaction(ctx, func(tx *gorm.DB) error {
		keyName := uuid.New().String()
		var err error
		var version string
		publicKey, version, err = client.backend.NewPrivateKey(ctx, keyName)
		if err != nil {
			return err
		}

		kid, err := namingFunc(publicKey)
		if err != nil {
			return err
		}
		ref = &orm.KeyReference{
			KID:     kid,
			KeyName: keyName,
			Version: version,
		}
		audit.Log(ctx, log.Logger(), audit.CryptoNewKeyEvent).Infof("Generated new key pair: %s", kid)
		return tx.Save(ref).Error
	})
	return ref, publicKey, err
}

// Delete removes the private key with the given KID from the KeyStore.
func (client *Crypto) Delete(ctx context.Context, kid string) error {
	return client.continueTransaction(ctx, func(tx *gorm.DB) error {
		// find the key_reference
		keyRef, err := client.findKeyReferenceByKid(ctx, kid)
		if err != nil {
			return err
		}
		audit.Log(ctx, log.Logger(), audit.CryptoDeleteKeyEvent).Infof("Deleting private key: %s", kid)
		err = tx.WithContext(ctx).Where("kid = ?", kid).Delete(&orm.KeyReference{}).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("could not delete key reference from DB: %w", err)
		}
		return client.backend.DeletePrivateKey(ctx, keyRef.KeyName)
	})
}

func (client *Crypto) Link(ctx context.Context, kid string, keyName string, version string) error {
	ref := &orm.KeyReference{
		KID:     kid,
		KeyName: keyName,
		Version: version,
	}
	return client.continueTransaction(ctx, func(tx *gorm.DB) error {
		return tx.Save(ref).Error
	})
}

// Exists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) Exists(ctx context.Context, kid string) (bool, error) {
	_, err := client.findKeyReferenceByKid(ctx, kid)
	if err != nil {
		if errors.Is(err, ErrPrivateKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (client *Crypto) Resolve(ctx context.Context, kid string) (crypto.PublicKey, error) {
	keyRef, err := client.findKeyReferenceByKid(ctx, kid)
	if err != nil {
		return nil, err
	}
	keypair, err := client.backend.GetPrivateKey(ctx, keyRef.KeyName, keyRef.Version)
	if err != nil {
		if errors.Is(err, spi.ErrNotFound) {
			return nil, ErrPrivateKeyNotFound
		}
		return nil, err
	}
	return keypair.Public(), nil
}

func (client *Crypto) findKeyReferenceByKid(ctx context.Context, kid string) (*orm.KeyReference, error) {
	var keyRef orm.KeyReference
	err := client.continueTransaction(ctx, func(tx *gorm.DB) error {
		err := tx.WithContext(ctx).Model(&orm.KeyReference{}).Where("kid = ?", kid).First(&keyRef).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrPrivateKeyNotFound
			}
			return fmt.Errorf("could not find key reference in DB: %w", err)
		}
		return nil
	})
	return &keyRef, err
}

func (client *Crypto) continueTransaction(ctx context.Context, op func(tx *gorm.DB) error) error {
	tx := client.db
	if val := ctx.Value(storage.TransactionKey{}); val != nil {
		tx = val.(*gorm.DB)
	}
	return op(tx)
}
