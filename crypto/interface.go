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

	"github.com/lestrrat-go/jwx/jwk"
)

// Client defines the functions than can be called by a Cmd, Direct or via rest call.
type Client interface {
	GenerateKeyPair() (crypto.PublicKey, error)
	// GetPrivateKey returns the specified private key (for e.g. signing) in non-exportable form.
	GetPrivateKey(kid string) (crypto.Signer, error)
	// GetPublicKeyAsPEM returns the PEM encoded PublicKey
	GetPublicKeyAsPEM(kid string) (string, error)
	// GetPublicKeyAsJWK returns the JWK encoded PublicKey for a given legal entity
	GetPublicKeyAsJWK(kid string) (jwk.Key, error)
	// SignJWT creates a signed JWT using the given key and map of claims (private key must be present).
	SignJWT(claims map[string]interface{}, kid string) (string, error)
	// PrivateKeyExists returns if the specified private key exists.
	PrivateKeyExists(key string) bool
}
