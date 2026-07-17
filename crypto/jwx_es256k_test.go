//go:build jwx_es256k

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestES256k verifies that, when built with the jwx_es256k tag, an ES256K-signed JWT
// round-trips through ParseJWT (i.e. ES256K is registered as a supported algorithm).
func TestES256k(t *testing.T) {
	// ES256K signs over the secp256k1 curve, so a P-256 key won't do.
	ecKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.New()
	signature, err := jwt.Sign(token, jwt.WithKey(jwa.ES256K(), ecKey))
	require.NoError(t, err)

	parsedToken, err := ParseJWT(string(signature), func(_ string) (crypto.PublicKey, error) {
		return ecKey.Public(), nil
	})
	require.NoError(t, err)
	assert.NotNil(t, parsedToken)
}
