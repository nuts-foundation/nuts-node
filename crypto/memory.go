/*
 * Copyright (C) 2024 Nuts community
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
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var _ JWTSigner = &MemoryJWTSigner{}
var errNotSupportedForInMemoryKeyStore = errors.New("not supported on in-memory key store")

// MemoryJWTSigner is a JWTSigner implementation that performs cryptographic operations on an in-memory JWK.
// This should only be used for low-assurance use cases, e.g. session-bound user keys.
type MemoryJWTSigner struct {
	Key jwk.Key
}

func (m MemoryJWTSigner) SignJWT(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, rawKey interface{}) (string, error) {
	keyID, ok := rawKey.(string)
	if !ok {
		return "", errors.New("key should be string (key ID)")
	}
	if keyID != m.Key.KeyID() {
		return "", ErrPrivateKeyNotFound
	}
	return signJWT(m.Key, claims, headers)
}

func (m MemoryJWTSigner) SignJWS(_ context.Context, _ []byte, _ map[string]interface{}, _ interface{}, _ bool) (string, error) {
	return "", errNotSupportedForInMemoryKeyStore
}
