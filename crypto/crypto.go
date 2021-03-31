/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"path"
	"time"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
)

const (
	moduleName = "Crypto"
	configKey  = "crypto"
)

// Config holds the values for the crypto engine
type Config struct {
	Storage string
}

// DefaultCryptoConfig returns a Config with sane defaults
func DefaultCryptoConfig() Config {
	return Config{
		Storage: "fs",
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
	return moduleName
}

func (client *Crypto) ConfigKey() string {
	return configKey
}

func (client *Crypto) Config() interface{} {
	return &client.config
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure(config core.ServerConfig) error {
	if client.config.Storage != "fs" && client.config.Storage != "" {
		return errors.New("only fs backend available for now")
	}
	var err error
	fsPath := path.Join(config.Datadir, "crypto")
	if client.Storage, err = storage.NewFileSystemBackend(fsPath); err != nil {
		return err
	}
	return nil
}

// New generates a new key pair.
// Stores the private key, returns the public key
// If a key is overwritten is handled by the storage implementation.
// (it's considered bad practise to reuse a kid for different keys)
func (client *Crypto) New(namingFunc KIDNamingFunc) (crypto.PublicKey, string, error) {
	keyPair, err := generateECKeyPair()
	if err != nil {
		return nil, "", err
	}

	kid, err := namingFunc(keyPair.Public())
	if err != nil {
		return nil, "", err
	}
	if err = client.Storage.SavePrivateKey(kid, keyPair); err != nil {
		return nil, "", fmt.Errorf("could not create new keypair: could not save private key: %w", err)
	}
	return keyPair.PublicKey, kid, nil
}

func generateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateKeyExists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) PrivateKeyExists(kid string) bool {
	return client.Storage.PrivateKeyExists(kid)
}

// GetPublicKey loads the key from storage
// It returns ErrKeyNotFound when the key could not be found in storage
// It returns ErrKeyRevoked when the key is not valid on the provided validationTime
func (client *Crypto) GetPublicKey(kid string, validationTime time.Time) (crypto.PublicKey, error) {
	pke, err := client.Storage.GetPublicKey(kid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, NewEntityErr(ErrKeyNotFound, kid)
		}
		return nil, err
	}

	if !pke.Period.Contains(validationTime) {
		return nil, NewEntityErr(ErrKeyRevoked, kid)
	}

	var unknown interface{}
	if err := pke.JWK().Raw(&unknown); err != nil {
		return nil, err
	}
	return unknown.(crypto.PublicKey), nil
}

// AddPublicKey save the public key to storage
// For validity the provided validFrom time is used.
// The key is valid until the end time which can be set using the RevokePublicKey method.
// It returns ErrKeyAlreadyExists when the key already exists
func (client *Crypto) AddPublicKey(kid string, publicKey crypto.PublicKey, validFrom time.Time) error {
	if kid == "" {
		return fmt.Errorf("could not add public key: kid cannot be empty")
	}
	key, err := jwk.New(publicKey)
	if err != nil {
		return err
	}
	// check if key already exists
	pkeyEntry, err := client.Storage.GetPublicKey(kid)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("could not add public key: unable to check key existance: %w", err)
		}
	}
	if pkeyEntry.Key != nil {
		return ErrKeyAlreadyExists
	}

	publicKeyEntry := storage.PublicKeyEntry{
		Period: core.Period{Begin: validFrom},
	}
	if err := publicKeyEntry.FromJWK(key); err != nil {
		return err
	}

	return client.Storage.SavePublicKey(kid, publicKeyEntry)
}

// RevokePublicKey revokes the key indicated by the kid from the given time by setting the end time on the PublicKeyEntry
// Returns ErrKeyNotFound when the indicated key is not present in the storage
// Returns ErrKeyRevoked when the end time on the PublicKeyEntry is already set
func (client *Crypto) RevokePublicKey(kid string, validTo time.Time) error {
	pkeyEntry, err := client.Storage.GetPublicKey(kid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	if pkeyEntry.Period.End != nil {
		return ErrKeyRevoked
	}
	pkeyEntry.Period.End = &validTo
	return client.Storage.SavePublicKey(kid, pkeyEntry)
}
