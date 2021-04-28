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
	// Signer TODO
	Signer(kid string) (KeySelector, error)

	KeyCreator

	JWSSigner
	JWTSigner
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

type KeySelector interface {
	// Signer TODO
	Signer() crypto.Signer

	KID() string

	Public() crypto.PublicKey
}
