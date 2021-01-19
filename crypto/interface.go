/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
)

// KidNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KidNamingFunc func(key crypto.PublicKey) (string, error)

type KeyCreator interface {
	// New generates a keypair and returns the public key.
	// the KidNamingFunc will provide the kid. priv/pub keys are appended with a postfix and stored
	New(namingFunc KidNamingFunc) (crypto.PublicKey, string, error)
}

// KeyStore defines the functions than can be called by a Cmd, Direct or via rest call.
type KeyStore interface {
	KeyCreator

	// GetPrivateKey returns the specified private key (for e.g. signing) in non-exportable form.
	// If a key is missing, a Storage.ErrNotFound is returned
	GetPrivateKey(kid string) (crypto.Signer, error)
	// GetPublicKey returns the PublicKey
	// If a key is missing, a Storage.ErrNotFound is returned
	GetPublicKey(kid string) (crypto.PublicKey, error)
	// SignJWT creates a signed JWT using the given key and map of claims (private key must be present).
	SignJWT(claims map[string]interface{}, kid string) (string, error)
	// PrivateKeyExists returns if the specified private key exists.
	// If an error occurs, false is also returned
	PrivateKeyExists(kid string) bool
}
