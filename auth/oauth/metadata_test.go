/*
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
 *
 */

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWellKnownCandidates(t *testing.T) {
	t.Run("identifier with path returns insert then append", func(t *testing.T) {
		candidates, err := wellKnownCandidates("https://nuts.nl/iam/id", true, AuthzServerWellKnown)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"https://nuts.nl/.well-known/oauth-authorization-server/iam/id",
			"https://nuts.nl/iam/id/.well-known/oauth-authorization-server",
		}, candidates)
	})
	t.Run("no path collapses to a single candidate", func(t *testing.T) {
		candidates, err := wellKnownCandidates("https://nuts.nl", true, AuthzServerWellKnown)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://nuts.nl/.well-known/oauth-authorization-server"}, candidates)
	})
	t.Run("trailing-slash-only path collapses to a single candidate", func(t *testing.T) {
		candidates, err := wellKnownCandidates("https://nuts.nl/", true, AuthzServerWellKnown)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://nuts.nl/.well-known/oauth-authorization-server"}, candidates)
	})
	t.Run("percent-encoded path is not double-escaped", func(t *testing.T) {
		candidates, err := wellKnownCandidates("https://nuts.nl/foo%2Fbar", true, OpenIdCredIssuerWellKnown)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"https://nuts.nl/.well-known/openid-credential-issuer/foo%2Fbar",
			"https://nuts.nl/foo%2Fbar/.well-known/openid-credential-issuer",
		}, candidates)
	})
	t.Run("invalid identifier returns the SSRF/parse error", func(t *testing.T) {
		candidates, err := wellKnownCandidates("http://nuts.nl/iam/id", true, AuthzServerWellKnown)
		assert.ErrorContains(t, err, "scheme must be https")
		assert.Nil(t, candidates)
	})
}

func TestFetchMetadata(t *testing.T) {
	ctx := context.Background()

	// metadataServer serves AuthorizationServerMetadata at the listed paths and returns
	// missStatus for any other path. The served issuer equals the server URL plus issuerPath,
	// so it matches an identifier of srv.URL+issuerPath. It records every requested path.
	metadataServer := func(t *testing.T, missStatus int, issuerPath string, servedPaths ...string) (*httptest.Server, *[]string) {
		var requested []string
		served := make(map[string]struct{}, len(servedPaths))
		var issuer string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested = append(requested, r.URL.Path)
			if _, ok := served[r.URL.Path]; ok {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{Issuer: issuer, TokenEndpoint: "/token"})
				return
			}
			w.WriteHeader(missStatus)
		}))
		t.Cleanup(srv.Close)
		issuer = srv.URL + issuerPath
		for _, p := range servedPaths {
			served[p] = struct{}{}
		}
		return srv, &requested
	}

	t.Run("ok - insert form, root identifier, single request", func(t *testing.T) {
		srv, requested := metadataServer(t, http.StatusNotFound, "", "/.well-known/oauth-authorization-server")

		metadata, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), srv.URL, false)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		assert.Equal(t, []string{"/.well-known/oauth-authorization-server"}, *requested)
	})
	t.Run("ok - append form when insert 404s", func(t *testing.T) {
		srv, requested := metadataServer(t, http.StatusNotFound, "/iam/123", "/iam/123/.well-known/oauth-authorization-server")

		metadata, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), srv.URL+"/iam/123", false)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, []string{
			"/.well-known/oauth-authorization-server/iam/123",
			"/iam/123/.well-known/oauth-authorization-server",
		}, *requested)
	})
	t.Run("identifier mismatch on first candidate falls through to next", func(t *testing.T) {
		var issuer string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server/iam/123":
				// 200 but with a non-matching issuer: must be rejected and fallen through.
				_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{Issuer: "https://attacker.example", TokenEndpoint: "/evil"})
			case "/iam/123/.well-known/oauth-authorization-server":
				_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{Issuer: issuer, TokenEndpoint: "/token"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)
		issuer = srv.URL + "/iam/123"

		metadata, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), issuer, false)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
	})
	t.Run("error - issuer with a trailing slash does not match the requested identifier", func(t *testing.T) {
		// RFC 8414 §3.3 / OpenID4VCI §12.2.4 require a byte-exact comparison, no normalization.
		var issuer string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/oauth/.well-known/oauth-authorization-server" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{Issuer: issuer + "/", TokenEndpoint: "/token"})
		}))
		t.Cleanup(srv.Close)
		issuer = srv.URL + "/oauth"

		_, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), issuer, false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match requested identifier")
	})
	t.Run("error - all candidates 404 names the identifier and the tried locations", func(t *testing.T) {
		srv, requested := metadataServer(t, http.StatusNotFound, "/iam/123")

		_, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), srv.URL+"/iam/123", false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve metadata")
		assert.Contains(t, err.Error(), srv.URL+"/iam/123")
		// Every tried location is listed in the error.
		assert.Contains(t, err.Error(), srv.URL+"/.well-known/oauth-authorization-server/iam/123")
		assert.Contains(t, err.Error(), srv.URL+"/iam/123/.well-known/oauth-authorization-server")
		assert.Len(t, *requested, 2)
	})
	t.Run("error - a candidate's core.HttpError stays recoverable through the join", func(t *testing.T) {
		srv, requested := metadataServer(t, http.StatusInternalServerError, "/iam/123")

		_, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), srv.URL+"/iam/123", false)

		require.Error(t, err)
		var httpErr core.HttpError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
		assert.Len(t, *requested, 2)
	})
	t.Run("error - invalid JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not valid json"))
		}))
		t.Cleanup(srv.Close)

		_, err := FetchMetadata[AuthorizationServerMetadata](ctx, srv.Client(), srv.URL, false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding metadata")
	})
	t.Run("error - invalid identifier is rejected before any request", func(t *testing.T) {
		_, err := FetchMetadata[AuthorizationServerMetadata](ctx, http.DefaultClient, "http://nuts.nl/iam/id", true)

		require.Error(t, err)
		assert.ErrorContains(t, err, "scheme must be https")
	})
}
