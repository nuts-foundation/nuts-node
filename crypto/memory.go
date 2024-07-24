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
	"crypto"
	"errors"
	"maps"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
)

var _ JWTSigner = &MemoryJWTSigner{}
var errNotSupportedForInMemoryKeyStore = errors.New("not supported on in-memory key store")

// MemoryJWTSigner is a JWTSigner implementation that performs cryptographic operations on an in-memory JWK.
// This should only be used for low-assurance use cases, e.g. session-bound user keys.
type MemoryJWTSigner struct {
	Key jwk.Key
}

func (m MemoryJWTSigner) SignJWT(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}, kid string) (string, error) {
	// copy headers so we don't change the input
	headersLocal := make(map[string]interface{})
	maps.Copy(headersLocal, headers)

	if kid != m.Key.KeyID() {
		return "", ErrPrivateKeyNotFound
	}
	var signer crypto.Signer
	if err := m.Key.Raw(&signer); err != nil {
		return "", err
	}
	alg, err := signingAlg(signer.Public())
	if err != nil {
		return "", err
	}

	headersLocal["kid"] = kid
	return SignJWT(ctx, signer, alg, claims, headersLocal)
}

func (m MemoryJWTSigner) SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, kid string, detached bool) (string, error) {
	var signer crypto.Signer
	if err := m.Key.Raw(&signer); err != nil {
		return "", err
	}

	if _, ok := headers["jwk"]; !ok {
		headers["kid"] = kid
	}
	return SignJWS(ctx, payload, headers, signer, detached)
}

func (m MemoryJWTSigner) SignDPoP(ctx context.Context, token dpop.DPoP, kid string) (string, error) {
	return "", errNotSupportedForInMemoryKeyStore
}
