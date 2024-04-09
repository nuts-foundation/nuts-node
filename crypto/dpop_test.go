/*
 * Nuts node
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
 */

package crypto

import (
	"encoding/base64"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPOP(t *testing.T) {
	client := createCrypto(t)
	privateKey, _ := client.New(audit.TestContext(), StringNamingFunc("kid"))
	keyAsJWK, _ := jwk.FromRaw(privateKey.Public())
	_ = keyAsJWK.Set(jwk.AlgorithmKey, jwa.ES256)
	request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

	t.Run("creates valid DPoP token", func(t *testing.T) {
		tokenString, err := client.NewDPoP(audit.TestContext(), *request, privateKey.KID(), nil)
		require.NoError(t, err)

		token, err := dpop.Parse(tokenString)
		require.NoError(t, err)

		assert.Equal(t, keyAsJWK, token.Headers.JWK())
		assert.Equal(t, "POST", token.HTM())
		assert.Equal(t, "https://server.example.com/token", token.HTU())
	})

	t.Run("creates valid DPoP proof for access token", func(t *testing.T) {
		accesstoken := "token"
		hashBytes := hash.SHA256Sum([]byte(accesstoken))
		hashString := base64.RawURLEncoding.EncodeToString(hashBytes.Slice())
		proofString, err := client.NewDPoP(audit.TestContext(), *request, privateKey.KID(), &accesstoken)
		require.NoError(t, err)

		proof, err := dpop.Parse(proofString)
		require.NoError(t, err)

		ath, ok := proof.Token.Get(dpop.ATHKey)
		require.True(t, ok)
		assert.Equal(t, hashString, ath)
	})
}
