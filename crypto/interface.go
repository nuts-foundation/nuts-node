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
	"errors"
	"fmt"
	"time"
)

// NewEntityErr wraps an error with new error containing the entity ID
// NewEntityErr(ErrKeyNotFound, id.String())
func NewEntityErr(err error, id string) error {
	return fmt.Errorf("%w: id: %s", err, id)
}

// ErrKeyNotFound is returned when the key should not exists but does
var ErrKeyNotFound = errors.New("key not found")

// ErrKeyRevoked is returned in situations that operations require an active key
var ErrKeyRevoked = errors.New("key is revoked")

// ErrKeyAlreadyExists is return in situations where a key should not exists but does
var ErrKeyAlreadyExists = errors.New("key already exists")

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)

// KeyCreator is the interface for creating key pairs.
type KeyCreator interface {
	// New generates a keypair and returns the public key.
	// the KIDNamingFunc will provide the kid. priv/pub keys are appended with a postfix and stored
	New(namingFunc KIDNamingFunc) (crypto.PublicKey, string, error)
}

// KeyResolver defines the functions for retrieving keys.
type KeyResolver interface {
	// GetPublicKey returns the PublicKey if it was valid on the given validationTime
	// If a key is missing, a ErrKeyNotFound is returned.
	GetPublicKey(kid string, validationTime time.Time) (crypto.PublicKey, error)
}

// PublicKeyStore defines the functions for retrieving and storing public keys.
type PublicKeyStore interface {
	KeyResolver

	// AddPublicKey stores a public key with a given kid and valid from date
	// The valid from determines the start of the period this key is valid
	// It returns an ErrKeyAlreadyExists if the key already exists
	AddPublicKey(kid string, publicKey crypto.PublicKey, validFrom time.Time) error

	// RevokePublicKey revokes a public key.
	// The validTo time determines end of the period the key was valid
	// It returns an ErrKeyNotFound when the key could not be found
	// It returns an ErrKeyRevoked error when the key was already revoked
	RevokePublicKey(kid string, validTo time.Time) error
}

type PrivateKeyChecker interface {
	// PrivateKeyExists returns if the specified private key exists.
	// If an error occurs, false is also returned
	PrivateKeyExists(kid string) bool
}

// PrivateKeyStore defines the functions for working with private keys.
type PrivateKeyStore interface {
	PrivateKeyChecker
	KeyCreator
	JWSSigner
	JWTSigner
}

// KeyStore defines the functions that can be called by a Cmd, Direct or via rest call.
type KeyStore interface {
	PublicKeyStore
	PrivateKeyStore
}

// JWSSigner defines the functions for signing JSON Web Signatures.
type JWSSigner interface {
	// SignJWS creates a signed JWS using the indicated key.
	// It contains protected headers and a payload.
	// Returns ErrKeyNotFound when indicated private key is not present.
	SignJWS(payload []byte, protectedHeaders map[string]interface{}, kid string) (string, error)
}

// JWTSigner is the interface used to sign authorization tokens.
type JWTSigner interface {
	// SignJWT creates a signed JWT using the indicated key and map of claims.
	// Returns ErrKeyNotFound when indicated private key is not present.
	SignJWT(claims map[string]interface{}, kid string) (string, error)
}
