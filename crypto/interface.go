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
)

// ErrKeyNotFound is returned when the key should not exists but does
var ErrKeyNotFound = errors.New("key not found")

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)

// KeyCreator is the interface for creating key pairs.
type KeyCreator interface {
	// New generates a keypair and returns the public key.
	// the KIDNamingFunc will provide the kid. priv/pub keys are appended with a postfix and stored
	New(namingFunc KIDNamingFunc) (KeySelector, error)
}

// KeyStore defines the functions for working with private keys.
type KeyStore interface {
	// PrivateKeyExists returns if the specified private key exists.
	// If an error occurs, false is also returned
	PrivateKeyExists(kid string) bool
	// Resolve returns a KeySelector for the given KID. ErrKeyNotFound is returned for an unknown KID.
	Resolve(kid string) (KeySelector, error)

	KeyCreator
	JWTSigner
}

// JWTSigner is the interface used to sign authorization tokens.
type JWTSigner interface {
	// SignJWT creates a signed JWT using the indicated key and map of claims.
	// Returns ErrKeyNotFound when indicated private key is not present.
	SignJWT(claims map[string]interface{}, kid string) (string, error)
}

// KeySelector is a helper interface which holds a crypto.Signer, KID and public key for a key.
type KeySelector interface {
	// Signer returns a crypto.Signer.
	Signer() crypto.Signer
	// KID returns the KID for the selected key.
	KID() string
	// Public returns the public key. This is a shirt-hand for Signer().Public()
	Public() crypto.PublicKey
}
