/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package spi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestPublicKeyEntry_UnmarshalJSON(t *testing.T) {
	t.Run("error - incorrect json", func(t *testing.T) {
		err := (&PublicKeyEntry{}).UnmarshalJSON([]byte("}"))
		assert.EqualError(t, err, "invalid character '}' looking for beginning of value")
	})

	t.Run("error - invalid publicKeyJwk format", func(t *testing.T) {
		err := (&PublicKeyEntry{}).UnmarshalJSON([]byte("{\"publicKeyJwk\":{}}"))
		assert.EqualError(t, err, "could not parse publicKeyEntry: invalid publickeyJwk: invalid key type from JSON ()")
	})
}

func TestPublicKeyEntry_FromJWK(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := jwk.New(privateKey)

	entry := PublicKeyEntry{}
	err := entry.FromJWK(pk)
	require.NoError(t, err)
	assert.NotEmpty(t, entry.Key)
	assert.Same(t, pk, entry.parsedJWK)
}
