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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/core"
)

// ErrNotFound indicates that the specified crypto storage entry couldn't be found.
var ErrNotFound = errors.New("entry not found")

// ErrKeyAlreadyExists indicates that a private key for this keyID already exists.
var ErrKeyAlreadyExists = errors.New("key already exists")

// Storage interface containing functions for storing and retrieving keys.
type Storage interface {
	core.HealthCheckable
	// GetPrivateKey from the storage backend and return its handler as an implementation of crypto.Signer.
	GetPrivateKey(ctx context.Context, kid string) (crypto.Signer, error)
	// PrivateKeyExists checks if the private key indicated with the kid is stored in the storage backend.
	PrivateKeyExists(ctx context.Context, kid string) bool
	// SavePrivateKey stores the key under the kid in the storage backend.
	SavePrivateKey(ctx context.Context, kid string, key crypto.PrivateKey) error
	// ListPrivateKeys returns the KIDs of the private keys that are present. Returns a []string(nil) if there was a problem.
	ListPrivateKeys(ctx context.Context) []string
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
