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

package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- RequestNonce ----

func TestClient_RequestNonce(t *testing.T) {
	t.Run("returns c_nonce from response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(NonceResponse{CNonce: "test-nonce-123"})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		nonce, err := client.RequestNonce(context.Background(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "test-nonce-123", nonce)
	})

	t.Run("error on non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.RequestNonce(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("error on empty c_nonce", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(NonceResponse{CNonce: ""})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.RequestNonce(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty c_nonce")
	})
}

// ---- OpenIDCredentialIssuerMetadata ----

func TestClient_OpenIDCredentialIssuerMetadata(t *testing.T) {
	t.Run("fetches and parses metadata from well-known path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-credential-issuer", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				NonceEndpoint:      "https://issuer.example.com/nonce",
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		metadata, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "https://issuer.example.com", metadata.CredentialIssuer)
		assert.Equal(t, "https://issuer.example.com/credential", metadata.CredentialEndpoint)
		assert.Equal(t, "https://issuer.example.com/nonce", metadata.NonceEndpoint)
	})

	t.Run("appends issuer path after well-known segment per RFC 8615", func(t *testing.T) {
		var capturedPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{CredentialIssuer: "x"})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL+"/oauth2/alice")
		require.NoError(t, err)
		assert.Equal(t, "/.well-known/openid-credential-issuer/oauth2/alice", capturedPath)
	})

	t.Run("error on non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("error on bad JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not valid json"))
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding issuer metadata")
	})
}

// ---- RequestCredential ----

func TestClient_RequestCredential(t *testing.T) {
	t.Run("posts request and parses response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

			var credReq CredentialRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&credReq))
			assert.Equal(t, "SomeCredentialConfig", credReq.CredentialConfigurationID)
			require.NotNil(t, credReq.Proofs)
			assert.Equal(t, []string{"proof-jwt-value"}, credReq.Proofs.JWT)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CredentialResponse{
				Credentials: []CredentialResponseEntry{
					{Credential: json.RawMessage(`"eyJhbGciOiJFUzI1NiJ9"`)},
				},
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		resp, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint:        srv.URL,
			AccessToken:               "test-token",
			CredentialConfigurationID: "SomeCredentialConfig",
			ProofJWT:                  "proof-jwt-value",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Credentials, 1)
		assert.JSONEq(t, `"eyJhbGciOiJFUzI1NiJ9"`, string(resp.Credentials[0].Credential))
	})

	t.Run("returns structured Error on invalid_nonce", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(Error{Code: InvalidNonce})
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint: srv.URL,
			AccessToken:        "test-token",
		})
		require.Error(t, err)

		var oidcErr Error
		require.True(t, errors.As(err, &oidcErr))
		assert.Equal(t, InvalidNonce, oidcErr.Code)
		assert.Equal(t, http.StatusBadRequest, oidcErr.StatusCode)
	})

	t.Run("returns generic error on non-2xx with no structured body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "something went wrong", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		client := NewClient(srv.Client())
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint: srv.URL,
			AccessToken:        "test-token",
		})
		require.Error(t, err)

		var oidcErr Error
		assert.False(t, errors.As(err, &oidcErr))
		assert.Contains(t, err.Error(), "503")
	})
}
