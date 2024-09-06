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

package spi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/core"
)

// ErrNotFound indicates that the specified crypto storage entry couldn't be found.
var ErrNotFound = errors.New("entry not found")

// ErrKeyAlreadyExists indicates that a private key for this keyID already exists.
var ErrKeyAlreadyExists = errors.New("key already exists")

// KidPattern is the regexp for acceptable kids
var KidPattern = regexp.MustCompile(`^(?:(?:[\da-zA-Z_\- :#.])|(?:%[0-9a-fA-F]{2}))+$`)

// Storage interface containing functions for storing and retrieving keys.
type Storage interface {
	core.HealthCheckable
	// NewPrivateKey creates a new private key. The backend will create the version and publicKey.
	// It should be preferred over generating a key in the application and saving it to the storage,
	// as it allows for unexportable (safer) keys.
	NewPrivateKey(ctx context.Context, keyName string) (crypto.PublicKey, string, error)
	// GetPrivateKey from the storage backend and return its handler as an implementation of crypto.Signer.
	GetPrivateKey(ctx context.Context, keyName string, version string) (crypto.Signer, error)
	// PrivateKeyExists checks if the private key indicated with the keyname/version is stored in the storage backend.
	PrivateKeyExists(ctx context.Context, keyName string, version string) (bool, error)
	// SavePrivateKey imports the key under the keyname in the storage backend.
	// see https://github.com/nuts-foundation/nuts-node/issues/3292
	SavePrivateKey(ctx context.Context, keyname string, key crypto.PrivateKey) error
	// ListPrivateKeys returns the KeyName and Version of the private keys that are present. Returns a []string(nil) if there was a problem.
	ListPrivateKeys(ctx context.Context) []KeyNameVersion
	// DeletePrivateKey removes the private key with the given keyname from the storage backend.
	DeletePrivateKey(ctx context.Context, keyName string) error
}

// KeyNameVersion contains a key name and version. It used as return argument for ListPrivateKeys.
type KeyNameVersion struct {
	KeyName string
	Version string
}

// PublicKeyEntry is a public key entry also containing the period it's valid for.
type PublicKeyEntry struct {
	Period    core.Period `json:"period"`
	parsedJWK jwk.Key
	Key       map[string]interface{} `json:"publicKeyJwk,omitempty"`
}

// FromJWK fills the publicKeyEntry with key material from the given key
func (pke *PublicKeyEntry) FromJWK(key jwk.Key) error {
	asMap, err := key.AsMap(context.Background())
	if err != nil {
		return err
	}
	pke.Key = asMap
	pke.parsedJWK = key
	return nil
}

// UnmarshalJSON parses the json
func (pke *PublicKeyEntry) UnmarshalJSON(bytes []byte) error {
	type Alias PublicKeyEntry
	tmp := Alias{}
	err := json.Unmarshal(bytes, &tmp)
	if err != nil {
		return err
	}
	*pke = (PublicKeyEntry)(tmp)
	if pke.Key != nil {
		jwkAsJSON, _ := json.Marshal(pke.Key)
		key, err := jwk.ParseKey(jwkAsJSON)
		if err != nil {
			return fmt.Errorf("could not parse publicKeyEntry: invalid publickeyJwk: %w", err)
		}
		pke.parsedJWK = key
	}
	return nil
}

// JWK returns the key as JSON Web Key.
func (pke PublicKeyEntry) JWK() jwk.Key {
	return pke.parsedJWK
}

// GenerateAndStore generates a new key pair and stores it in the provided storage.
func GenerateAndStore(ctx context.Context, store Storage, keyName string) (crypto.PublicKey, string, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	exists, err := store.PrivateKeyExists(ctx, keyName, "1")
	if err != nil {
		return nil, "", fmt.Errorf("could not create new keypair: could not check if key already exists: %w", err)
	}
	if exists {
		return nil, "", errors.New("key with the given ID already exists")
	}
	if err = store.SavePrivateKey(ctx, keyName, keyPair); err != nil {
		return nil, "", fmt.Errorf("could not create new keypair: could not save private key: %w", err)
	}
	return keyPair.Public(), "1", nil
}

// GenerateKeyPair generates a new key pair using the default key type.
// It's intended to be used by crypto backends that don't create unexportable keys.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
