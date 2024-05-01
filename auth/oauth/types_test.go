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

package oauth

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIssuerIdToWellKnown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/id", u.String())
	})
	t.Run("no path in issuer", func(t *testing.T) {
		issuer := "https://nuts.nl"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server", u.String())
	})
	t.Run("don't unescape path", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/%2E%2E/still-has-iam"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/%2E%2E/still-has-iam", u.String())
	})
	t.Run("https in strictmode", func(t *testing.T) {
		issuer := "http://nuts.nl/iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "scheme must be https")
		assert.Nil(t, u)
	})
	t.Run("no IP allowed", func(t *testing.T) {
		issuer := "https://127.0.0.1/iam/id"

		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)

		assert.ErrorContains(t, err, "hostname is IP")
		assert.Nil(t, u)
	})
	t.Run("invalid URL", func(t *testing.T) {
		issuer := "http:// /iam/id"
		u, err := IssuerIdToWellKnown(issuer, AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "invalid character \" \" in host name")
		assert.Nil(t, u)
	})
}

func TestTokenResponse_Marshalling(t *testing.T) {
	expected := TokenResponse{
		AccessToken: "1234567",
		ExpiresIn:   new(int),
		TokenType:   "bearer",
		Scope:       new(string),
	}
	*expected.ExpiresIn = 5
	*expected.Scope = "abc"
	expected.WithParam("c_nonce", "hello")

	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(expected)
		require.NoError(t, err)
		assert.JSONEq(t, `{"access_token":"1234567","expires_in":5,"token_type":"bearer","scope":"abc","c_nonce":"hello"}`, string(data))
	})
	t.Run("unmarshal", func(t *testing.T) {
		data, _ := json.Marshal(expected)
		var actual TokenResponse
		err := json.Unmarshal(data, &actual)
		require.NoError(t, err)
		assert.Equal(t, expected, actual)

		assert.Equal(t, *actual.GetString("c_nonce"), "hello")
	})
}

func TestTokenResponse_GetString(t *testing.T) {
	t.Run("nil map", func(t *testing.T) {
		var tr TokenResponse
		assert.Nil(t, tr.GetString("c_nonce"))
	})
}
