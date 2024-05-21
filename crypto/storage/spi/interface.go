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
	// NewPrivateKey creates a new private key and returns its handler as an implementation of crypto.Signer.
	// It should be preferred over generating a key in the application and saving it to the storage,
	// as it allows for unexportable (safer) keys. If the resulting kid already exists, it returns an error
	NewPrivateKey(ctx context.Context, namingFunc func(crypto.PublicKey) (string, error)) (crypto.PublicKey, string, error)
	// GetPrivateKey from the storage backend and return its handler as an implementation of crypto.Signer.
	GetPrivateKey(ctx context.Context, kid string) (crypto.Signer, error)
	// PrivateKeyExists checks if the private key indicated with the kid is stored in the storage backend.
	PrivateKeyExists(ctx context.Context, kid string) (bool, error)
	// SavePrivateKey imports the key under the kid in the storage backend.
	SavePrivateKey(ctx context.Context, kid string, key crypto.PrivateKey) error
	// ListPrivateKeys returns the KIDs of the private keys that are present. Returns a []string(nil) if there was a problem.
	ListPrivateKeys(ctx context.Context) []string
	// DeletePrivateKey removes the private key with the given KID from the storage backend.
	DeletePrivateKey(ctx context.Context, kid string) error
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

func GenerateAndStore(ctx context.Context, store Storage, namingFunc func(crypto.PublicKey) (string, error)) (crypto.PublicKey, string, error) {
	keyPair, kid, err := GenerateKeyPairAndKID(namingFunc)
	if err != nil {
		return nil, "", err
	}
	if store.PrivateKeyExists(ctx, kid) {
		return nil, "", errors.New("key with the given ID already exists")
	}
	if err = store.SavePrivateKey(ctx, kid, keyPair); err != nil {
		return nil, "", fmt.Errorf("could not create new keypair: could not save private key: %w", err)
	}
	return keyPair.Public(), kid, nil
}

// GenerateKeyPair generates a new key pair using the default key type.
// It's intended to be used by crypto backends that don't create unexportable keys.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateKeyPairAndKID generates a new key pair and a KID using the provided naming function.
// It's intended to be used by crypto backends that don't create unexportable keys.
func GenerateKeyPairAndKID(namingFunc func(crypto.PublicKey) (string, error)) (*ecdsa.PrivateKey, string, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}

	kid, err := namingFunc(keyPair.Public())
	if err != nil {
		return nil, "", err
	}

	return keyPair, kid, nil
}
