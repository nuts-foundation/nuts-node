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
)

// ErrPrivateKeyNotFound is returned when the private key doesn't exist
var ErrPrivateKeyNotFound = errors.New("private key not found")

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)

// KeyCreator is the interface for creating key pairs.
type KeyCreator interface {
	// New generates a keypair and returns a Key. The context is used to pass audit information.
	// The KIDNamingFunc will provide the kid.
	New(ctx context.Context, namingFunc KIDNamingFunc) (Key, error)
}

// KeyResolver is the interface for resolving keys.
type KeyResolver interface {
	// Exists returns if the specified private key exists.
	// If an error occurs, false is also returned
	Exists(ctx context.Context, kid string) bool
	// Resolve returns a Key for the given KID. ErrPrivateKeyNotFound is returned for an unknown KID.
	Resolve(ctx context.Context, kid string) (Key, error)
	// List returns the KIDs of the private keys that are present in the KeyStore.
	List(ctx context.Context) []string
}

// KeyStore defines the functions for working with private keys.
type KeyStore interface {
	Decrypter
	KeyCreator
	KeyResolver
	JWTSigner
}

// Decrypter is the interface to support decryption
type Decrypter interface {
	// Decrypt decrypts the `cipherText` with key `kid`
	// The context is used to pass audit information.
	// Note: decryption isn't audit logged, because:
	// - it involved very deep context passing,
	// - it's called by the system itself, not triggered by a user.
	// - to be removed in near future when we switch to multi-chains, which eliminates private TXs and thus encryption altogether.
	Decrypt(ctx context.Context, kid string, ciphertext []byte) ([]byte, error)
}

// JWTSigner is the interface used to sign authorization tokens.
type JWTSigner interface {
	// SignJWT creates a signed JWT using the indicated key and map of claims.
	// The key can be its KID (key ID) or an instance of Key,
	// the context is used to pass audit information.
	// Returns ErrPrivateKeyNotFound when the private is not present.
	SignJWT(ctx context.Context, claims map[string]interface{}, key interface{}) (string, error)
	// SignJWS creates a signed JWS using the indicated key and map of headers and payload as bytes.
	// The detached boolean indicates if the body needs to be excluded from the response (detached mode).
	// The key can be its KID (key ID) or an instance of Key,
	// context is used to pass audit information.
	// Returns ErrPrivateKeyNotFound when the private key is not present.
	SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, key interface{}, detached bool) (string, error)

	// EncryptJWE encrypts a payload as bytes into a JWE message with the given key and kid.
	// The publicKey must be a public key
	// The kid must be the KeyID and will be placed in the header, if not set.
	EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error)

	// DecryptJWE decrypts a message as bytes into a decrypted body and headers.
	// The corresponding private key must be located in the KeyID (kid) header.
	DecryptJWE(ctx context.Context, message string) (body []byte, headers map[string]interface{}, err error)
}

// Key is a helper interface that describes a private key in the crypto module, specifying its KID and public part.
type Key interface {
	// KID returns the unique ID for this key.
	KID() string
	// Public returns the public key.
	Public() crypto.PublicKey
}

// exportableKey is a Key that contains the private key itself and thus is exportable.
// Should only be used for select purposes (e.g. ephemeral keys).
type exportableKey interface {
	Key
	// Signer returns the private key.
	Signer() crypto.Signer
}
