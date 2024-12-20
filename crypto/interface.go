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
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/nuts-foundation/nuts-node/storage/orm"
)

// ErrPrivateKeyNotFound is returned when the private key doesn't exist
var ErrPrivateKeyNotFound = errors.New("private key not found")

// ErrorInvalidNumberOfSignatures indicates that the number of signatures present in the JWT is invalid.
var ErrorInvalidNumberOfSignatures = errors.New("invalid number of signatures")

// KIDNamingFunc is a function passed to New() which generates the kid for the pub/priv key
type KIDNamingFunc func(key crypto.PublicKey) (string, error)

// KeyCreator is the interface for creating key pairs.
type KeyCreator interface {
	// New generates a keypair and returns a reference. The context is used to pass audit information.
	// It generates a key at the backend and stores its reference in the SQL DB.
	// A DB transaction may be passed through the context using `orm.TransactionKey`.
	New(ctx context.Context, namingFunc KIDNamingFunc) (*orm.KeyReference, crypto.PublicKey, error)
}

// KeyResolver is the interface for resolving keys.
type KeyResolver interface {
	// Exists returns if the specified private key exists.
	// If an error occurs, false is also returned
	Exists(ctx context.Context, kid string) (bool, error)
	// Resolve returns a Key for the given KID. ErrPrivateKeyNotFound is returned for an unknown KID.
	Resolve(ctx context.Context, kid string) (crypto.PublicKey, error)
	// List returns the KIDs of the private keys that are present in the KeyStore.
	List(ctx context.Context) []string
}

// KeyStore defines the functions for working with private keys.
type KeyStore interface {
	Decrypter
	JsonWebEncryptor
	KeyCreator
	KeyResolver
	JWTSigner

	// Delete removes the private key with the given KID from the KeyStore.
	Delete(ctx context.Context, kid string) error

	// Link links the key in the keystore to a kid
	// see https://github.com/nuts-foundation/nuts-node/issues/3292
	Link(ctx context.Context, kid string, keyName string, version string) error
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
	// SignJWT creates a signed JWT using the indicated key and map of claims and additional headers.
	// The KID is the external facing Key ID (eg: from the DID Document). the context is used to pass audit information.
	// The headers can be used to add/override headers in the JWT.
	// Returns ErrPrivateKeyNotFound when the private key is not present.
	SignJWT(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}, kid string) (string, error)
	// SignJWS creates a signed JWS using the indicated key and map of headers and payload as bytes.
	// The detached boolean indicates if the body needs to be excluded from the response (detached mode).
	// The KID is the external facing Key ID (eg: from the DID Document).
	// context is used to pass audit information.
	// Returns ErrPrivateKeyNotFound when the private key is not present.
	SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, kid string, detached bool) (string, error)
	// SignDPoP signs a DPoP token for the given kid.
	// It adds the requested key as jwk header to the DPoP token.
	SignDPoP(ctx context.Context, token dpop.DPoP, kid string) (string, error)
}

// JsonWebEncryptor is the interface used to encrypt and decrypt JWE messages.
type JsonWebEncryptor interface {
	// EncryptJWE encrypts a payload as bytes into a JWE message with the given key and kid.
	// The publicKey must be a public key
	// The kid must be the KeyID and will be placed in the header, if not set.
	EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error)

	// DecryptJWE decrypts a message as bytes into a decrypted body and headers.
	// The corresponding private key must be located in the KeyID (kid) header.
	DecryptJWE(ctx context.Context, message string) (body []byte, headers map[string]interface{}, err error)
}
