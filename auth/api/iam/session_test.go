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

package iam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserWallet_Key(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keyAsJWK, err := jwk.FromRaw(pk)
		require.NoError(t, err)
		jwkAsJSON, _ := json.Marshal(keyAsJWK)
		wallet := UserWallet{
			JWK: jwkAsJSON,
		}
		key, err := wallet.Key()
		require.NoError(t, err)
		assert.Equal(t, keyAsJWK, key)
	})
}
