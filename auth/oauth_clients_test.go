/*
 * Nuts node
 * Copyright (C) 2026 Nuts community
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

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authWithClients(clients ...OAuthClientConfig) *Auth {
	return &Auth{config: Config{Experimental: ExperimentalConfig{Clients: clients}}}
}

func TestAuth_OAuthClientCredentials(t *testing.T) {
	cfg := OAuthClientConfig{ServerURL: "https://issuer.example.com/oauth", ClientID: "client-1", ClientSecret: "secret"}
	a := authWithClients(cfg)

	t.Run("match", func(t *testing.T) {
		got, ok := a.OAuthClientCredentials("https://issuer.example.com/oauth")
		require.True(t, ok)
		assert.Equal(t, "client-1", got.ClientID)
		assert.Equal(t, "secret", got.ClientSecret)
	})
	t.Run("match ignores a trailing slash difference", func(t *testing.T) {
		got, ok := a.OAuthClientCredentials("https://issuer.example.com/oauth/")
		require.True(t, ok)
		assert.Equal(t, "client-1", got.ClientID)
	})
	t.Run("no match returns false", func(t *testing.T) {
		got, ok := a.OAuthClientCredentials("https://other.example.com/oauth")
		assert.False(t, ok)
		assert.Nil(t, got)
	})
	t.Run("no configured clients returns false", func(t *testing.T) {
		got, ok := (&Auth{}).OAuthClientCredentials("https://issuer.example.com/oauth")
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}

func TestAuth_validateOAuthClients(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a := authWithClients(OAuthClientConfig{ServerURL: "https://nuts-services.nl/oauth", ClientID: "client-1"})
		assert.NoError(t, a.validateOAuthClients(true))
	})
	t.Run("empty (no clients) is valid", func(t *testing.T) {
		assert.NoError(t, (&Auth{}).validateOAuthClients(true))
	})
	t.Run("missing serverurl", func(t *testing.T) {
		a := authWithClients(OAuthClientConfig{ClientID: "client-1"})
		assert.EqualError(t, a.validateOAuthClients(true), "auth.experimental.clients[0]: serverurl is required")
	})
	t.Run("missing clientid", func(t *testing.T) {
		a := authWithClients(OAuthClientConfig{ServerURL: "https://nuts-services.nl/oauth"})
		assert.EqualError(t, a.validateOAuthClients(true), "auth.experimental.clients[0]: clientid is required")
	})
	t.Run("invalid serverurl in strict mode (not HTTPS)", func(t *testing.T) {
		a := authWithClients(OAuthClientConfig{ServerURL: "http://nuts-services.nl/oauth", ClientID: "client-1"})
		assert.ErrorContains(t, a.validateOAuthClients(true), "auth.experimental.clients[0]: invalid serverurl")
	})
	t.Run("duplicate serverurl", func(t *testing.T) {
		a := authWithClients(
			OAuthClientConfig{ServerURL: "https://nuts-services.nl/oauth", ClientID: "client-1"},
			OAuthClientConfig{ServerURL: "https://nuts-services.nl/oauth/", ClientID: "client-2"},
		)
		assert.ErrorContains(t, a.validateOAuthClients(true), "duplicate serverurl")
	})
}
