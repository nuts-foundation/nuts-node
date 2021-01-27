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
	"time"

	"github.com/nuts-foundation/nuts-node/core"
)

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)

// KeyCreator is the interface for creating key pairs.
type KeyCreator interface {
	// New generates a keypair and returns the public key.
	// the KIDNamingFunc will provide the kid. priv/pub keys are appended with a postfix and stored
	New(namingFunc KIDNamingFunc) (crypto.PublicKey, string, error)
}

// fill from diff
type KeyResolver interface {
	// GetPublicKey returns the PublicKey if it was valid on the given validationTime
	// If a key is missing, a Storage.ErrNotFound is returned.
	GetPublicKey(kid string, validationTime time.Time) (crypto.PublicKey, error)
}

// PublicKeyStore defines the functions for retrieving and storing public keys.
type PublicKeyStore interface {
	KeyResolver

	// SavePublicKey stores or overwrites a public key with a given kid.
	// The validity period defines when the given key is valid.
	SavePublicKey(kid string, publicKey crypto.PublicKey, period core.Period) error
}

// KeyStore defines the functions that can be called by a Cmd, Direct or via rest call.
type KeyStore interface {
	KeyCreator
	PublicKeyStore
	DocSigner
	AuthSigner
	// PrivateKeyExists returns if the specified private key exists.
	// If an error occurs, false is also returned
	PrivateKeyExists(kid string) bool
}

// DocSigner defines the functions for signing JSON Web Signatures.
type DocSigner interface {
	// SignJWS creates a signed JWS (in compact form using) the given key (private key must be present), protected headers and payload.
	SignJWS(payload []byte, protectedHeaders map[string]interface{}, kid string) (string, error)
}

// AuthSigner is the interface used to sign authorization tokens
type AuthSigner interface {
	// SignJWT creates a signed JWT using the given key and map of claims (private key must be present).
	SignJWT(claims map[string]interface{}, kid string) (string, error)
}
