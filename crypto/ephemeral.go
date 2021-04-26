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
 *
 */

package crypto

import (
	"crypto"
	"crypto/ecdsa"

	"github.com/lestrrat-go/jwx/jwk"
)

// NewEphemeralKeyStore returns a Accessor with a single key for single use.
func NewEphemeralKeyStore() Accessor {
	key, err := generateECKeyPair()
	return &ephemeralKeyStore {
		privateKey: key,
		err: err,
	}
}

type ephemeralKeyStore struct {
	privateKey *ecdsa.PrivateKey
	kid        string
	err        error
}

func (e ephemeralKeyStore) PrivateKeyExists(kid string) bool {
	return e.kid == kid
}

func (e *ephemeralKeyStore) New(namingFunc KIDNamingFunc) (crypto.PublicKey, string, error) {
	if e.err != nil {
		return nil, "", e.err
	}

	pub := e.privateKey.Public()
	e.kid, e.err = namingFunc(pub)

	return pub, e.kid, e.err
}

func (e *ephemeralKeyStore) Signer(kid string) (crypto.Signer, error) {
	if e.kid == kid {
		return e.privateKey, nil
	}

	return nil, ErrKeyNotFound
}

// SignJWS creates a signed JWS (in compact form using) the given key (private key must be present), protected headers and payload.
func (e *ephemeralKeyStore) SignJWS(payload []byte, protectedHeaders map[string]interface{}, kid string) (string, error) {
	if kid != kid {
		return "", ErrKeyNotFound
	}

	return signJWS(payload, protectedHeaders, e.privateKey)
}

func (e ephemeralKeyStore) SignJWT(claims map[string]interface{}, kid string) (string, error) {
	if kid != kid {
		return "", ErrKeyNotFound
	}

	key, err := jwkKey(e.privateKey)
	if err != nil {
		return "", err
	}

	if err = key.Set(jwk.KeyIDKey, kid); err != nil {
		return "", err
	}

	return SignJWT(key, claims, nil)
}
