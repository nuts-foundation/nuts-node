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

	"github.com/nuts-foundation/nuts-node/auth/oauth"
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

		client := NewClient(srv.Client(), false)
		nonce, err := client.RequestNonce(context.Background(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "test-nonce-123", nonce)
	})

	t.Run("error on non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
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

		client := NewClient(srv.Client(), false)
		_, err := client.RequestNonce(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty c_nonce")
	})
}

// ---- OpenIDCredentialIssuerMetadata ----

func TestClient_OpenIDCredentialIssuerMetadata(t *testing.T) {
	t.Run("fetches and parses metadata from well-known path", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-credential-issuer", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{
				CredentialIssuer:   srv.URL,
				CredentialEndpoint: srv.URL + "/credential",
				NonceEndpoint:      srv.URL + "/nonce",
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		metadata, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, srv.URL, metadata.CredentialIssuer)
		assert.Equal(t, srv.URL+"/credential", metadata.CredentialEndpoint)
		assert.Equal(t, srv.URL+"/nonce", metadata.NonceEndpoint)
	})

	t.Run("appends issuer path after well-known segment per RFC 8615", func(t *testing.T) {
		var capturedPath string
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{CredentialIssuer: srv.URL + "/oauth2/alice"})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL+"/oauth2/alice")
		require.NoError(t, err)
		assert.Equal(t, "/.well-known/openid-credential-issuer/oauth2/alice", capturedPath)
	})

	t.Run("preserves percent-encoded path segments without double-escaping", func(t *testing.T) {
		var capturedRawPath string
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRawPath = r.URL.EscapedPath()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{CredentialIssuer: srv.URL + "/foo%2Fbar"})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL+"/foo%2Fbar")
		require.NoError(t, err)
		assert.Equal(t, "/.well-known/openid-credential-issuer/foo%2Fbar", capturedRawPath)
	})

	t.Run("rejects metadata when credential_issuer mismatches requested issuer", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDCredentialIssuerMetadata{
				CredentialIssuer: "https://attacker.example/",
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential_issuer")
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("error on non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("rejects non-https issuer URL in strict mode", func(t *testing.T) {
		client := NewClient(http.DefaultClient, true)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), "http://issuer.example/")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL")
	})

	t.Run("rejects issuer URL with query or fragment per §12.2.1", func(t *testing.T) {
		client := NewClient(http.DefaultClient, false)
		_, err := client.OpenIDCredentialIssuerMetadata(context.Background(), "https://issuer.example/?foo=bar")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "query and fragment")

		_, err = client.OpenIDCredentialIssuerMetadata(context.Background(), "https://issuer.example/#section")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "query and fragment")
	})

	t.Run("error on bad JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not valid json"))
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
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

		client := NewClient(srv.Client(), false)
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

	t.Run("uses credential_identifier when provided and omits credential_configuration_id", func(t *testing.T) {
		var credReq CredentialRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&credReq))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CredentialResponse{
				Credentials: []CredentialResponseEntry{{Credential: json.RawMessage(`"vc"`)}},
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint:        srv.URL,
			AccessToken:               "t",
			CredentialConfigurationID: "ignored-when-identifier-set",
			CredentialIdentifier:      "CivilEngineeringDegree-2023",
			ProofJWT:                  "p",
		})
		require.NoError(t, err)
		assert.Equal(t, "CivilEngineeringDegree-2023", credReq.CredentialIdentifier)
		assert.Empty(t, credReq.CredentialConfigurationID, "credential_configuration_id MUST NOT be present when credential_identifier is used (§8.2)")
	})

	t.Run("returns structured oauth.OAuth2Error on invalid_nonce", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(oauth.OAuth2Error{Code: oauth.InvalidNonce})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint: srv.URL,
			AccessToken:        "test-token",
		})
		require.Error(t, err)

		var oauthErr oauth.OAuth2Error
		require.True(t, errors.As(err, &oauthErr))
		assert.Equal(t, oauth.InvalidNonce, oauthErr.Code)
	})

	t.Run("CredentialDetails replaces body; only proofs is node-built", func(t *testing.T) {
		var rawBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&rawBody))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CredentialResponse{
				Credentials: []CredentialResponseEntry{{Credential: json.RawMessage(`"vc"`)}},
			})
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint:        srv.URL,
			AccessToken:               "t",
			CredentialConfigurationID: "IgnoredWhenDetailsSet",
			ProofJWT:                  "node-proof",
			CredentialDetails: map[string]any{
				"credential_identifier": "HealthCareProfessionalDelegationCredential",
				"bsn":                   "900184590",
				"ura":                   "900030757",
				// caller-supplied proofs MUST be overwritten by the node-built one
				"proofs": map[string]any{"jwt": []string{"caller-supplied-proof"}},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "HealthCareProfessionalDelegationCredential", rawBody["credential_identifier"])
		assert.Equal(t, "900184590", rawBody["bsn"])
		assert.Equal(t, "900030757", rawBody["ura"])
		assert.NotContains(t, rawBody, "credential_configuration_id", "typed credential_* fields must NOT be set when CredentialDetails is used")
		assert.Equal(t, map[string]any{"jwt": []any{"node-proof"}}, rawBody["proofs"])
	})

	t.Run("returns generic error on non-2xx with no structured body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "something went wrong", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		client := NewClient(srv.Client(), false)
		_, err := client.RequestCredential(context.Background(), RequestCredentialOpts{
			CredentialEndpoint: srv.URL,
			AccessToken:        "test-token",
		})
		require.Error(t, err)

		var oauthErr oauth.OAuth2Error
		assert.False(t, errors.As(err, &oauthErr))
		assert.Contains(t, err.Error(), "503")
	})
}
