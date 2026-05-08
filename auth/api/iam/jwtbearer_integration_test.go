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

package iam_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/test/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_JwtBearer_TwoVPHappyPath boots a real Nuts node, provisions four subjects
// (CIBG issuer, Twiin issuer, HCP organization, service provider), issues the three credentials
// needed to satisfy the medication-overview profile (HealthcareProviderCredential,
// ServiceProviderCredential, ServiceProviderDelegationCredential), drives the API endpoint, and
// asserts the captured token-request form body matches the RFC 7523 jwt-bearer wire format and
// both VPs verify cleanly through the same node's /internal/vcr/v2/verifier/vp endpoint.
//
// Negative paths (feature flag off, AS doesn't advertise jwt-bearer, missing service_provider PD,
// SP wallet has no matching credentials) are covered by the unit tests in
// auth/client/iam/openid4vp_test.go and the handler tests in auth/api/iam/api_test.go; this
// integration test focuses on the happy-path round trip that those mock-based tests cannot
// cover: real cryptographic signing, real DID resolution, and real verifyVP.
func TestIntegration_JwtBearer_TwoVPHappyPath(t *testing.T) {
	policyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "medication-overview.json"), []byte(medicationOverviewPolicy), 0o644))

	// Mock authorization server: serves AS metadata advertising jwt-bearer support and captures
	// the form body POSTed to /token. Set up before the node so we can include its URL in the
	// node config (not strictly required since metadata fetch is from the AS itself, but keeps
	// the wiring obvious).
	asMock := newMockAS(t)
	defer asMock.server.Close()

	internalURL, _, _ := node.StartServer(t, func(_, _ string) {
		t.Setenv("NUTS_AUTH_EXPERIMENTAL_JWTBEARERCLIENT", "true")
		t.Setenv("NUTS_DIDMETHODS", "web")
		t.Setenv("NUTS_POLICY_DIRECTORY", policyDir)
	})

	const (
		cibgSubject  = "cibg-issuer"
		twiinSubject = "twiin-issuer"
		orgSubject   = "org1"
		spSubject    = "sp1"
		ura          = "78551223"
	)

	cibgDID := provisionSubject(t, internalURL, cibgSubject)
	twiinDID := provisionSubject(t, internalURL, twiinSubject)
	orgDID := provisionSubject(t, internalURL, orgSubject)
	spDID := provisionSubject(t, internalURL, spSubject)

	// HCP credential: CIBG → org. Asserts the org is a healthcare provider with the given URA.
	issueAndLoad(t, internalURL, orgSubject, buildHCPCredential(cibgDID, orgDID, ura))
	// SP credential: Twiin → sp. Required by the service_provider PD's first input descriptor.
	issueAndLoad(t, internalURL, spSubject, buildSPCredential(twiinDID, spDID))
	// Delegation credential: org → sp. The cross-VP binding ties this credential's `issuer`
	// (orgDID) and its delegatedBy URA back to VP1's HCP credential.
	issueAndLoad(t, internalURL, spSubject, buildDelegationCredential(orgDID, spDID, ura))

	// Drive the API.
	body := map[string]any{
		"authorization_server":        asMock.server.URL + "/oauth2/" + spSubject,
		"scope":                       "medication-overview",
		"service_provider_subject_id": spSubject,
		"token_type":                  "Bearer",
	}
	bodyBytes, _ := json.Marshal(body)
	resp, err := http.Post(internalURL+"/internal/auth/v2/"+orgSubject+"/request-service-access-token",
		"application/json", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "request-service-access-token failed: %s", respBody)

	// Wire-format assertions on the captured form body.
	form := asMock.lastForm()
	assert.Equal(t, oauth.JwtBearerGrantType, form.Get("grant_type"), "grant_type")
	assert.Equal(t, oauth.JwtBearerClientAssertionType, form.Get("client_assertion_type"), "client_assertion_type")
	assert.Equal(t, "medication-overview", form.Get("scope"), "scope")
	assert.NotEmpty(t, form.Get("assertion"), "assertion (VP1)")
	assert.NotEmpty(t, form.Get("client_assertion"), "client_assertion (VP2)")
	assert.Empty(t, form.Get("presentation_submission"), "presentation_submission must not be set per RFC 7523")
	assert.Empty(t, form.Get("client_id"), "client_id must not be set on jwt-bearer (RFC 7521 §4.2)")

	// Round-trip both VPs through the same node's verifier.
	hcpVP := verifyVP(t, internalURL, form.Get("assertion"))
	delegationVP := verifyVP(t, internalURL, form.Get("client_assertion"))

	// Cross-VP binding survived end-to-end: the delegation credential's issuer equals the
	// organization's DID (the same DID that signed VP1), and its delegatedBy URA equals the
	// HCP credential's URA.
	delegationCred := pluckCredentialByType(t, delegationVP, "ServiceProviderDelegationCredential")
	assert.Equal(t, orgDID, jsonString(t, delegationCred, "issuer"),
		"delegation credential issuer must equal VP1 signer (cross-VP binding on $.issuer == $.credentialSubject.id)")
	assert.Equal(t, ura, deepString(t, delegationCred, "credentialSubject", 0, "hasDelegation", "delegatedBy", "identifier", 0, "value"),
		"delegation delegatedBy URA must equal VP1 HCP URA (cross-VP binding on URA)")

	// Sanity: VP1 (organization VP) carried the HCP credential.
	hcpCred := pluckCredentialByType(t, hcpVP, "HealthcareProviderCredential")
	assert.Equal(t, ura, deepString(t, hcpCred, "credentialSubject", 0, "identifier", 0, "value"),
		"HCP credential carries the expected URA")
}

// medicationOverviewPolicy defines an organization PD on HealthcareProviderCredential and a
// service_provider PD with two input descriptors (ServiceProviderCredential and
// ServiceProviderDelegationCredential). The two PDs share two field IDs that realise the
// cross-VP binding:
//
//   - delegating_hcp:     HCP cred's $.credentialSubject.id  ↔  Delegation cred's $.issuer
//   - delegating_hcp_ura: HCP cred's URA value              ↔  Delegation cred's delegatedBy URA
//
// Both must equal across the two VPs for the SP wallet's submission to satisfy the PD.
const medicationOverviewPolicy = `{
  "medication-overview": {
    "organization": {
      "id": "pd_org",
      "format": {
        "jwt_vc": {"alg": ["ES256", "PS256", "RS256"]},
        "jwt_vp": {"alg": ["ES256", "PS256", "RS256"]}
      },
      "input_descriptors": [{
        "id": "id_hcp",
        "constraints": {
          "fields": [
            {"path": ["$.type"], "filter": {"type": "string", "const": "HealthcareProviderCredential"}},
            {"id": "delegating_hcp", "path": ["$.credentialSubject[0].id", "$.credentialSubject.id"], "filter": {"type": "string"}},
            {"id": "delegating_hcp_ura", "path": ["$.credentialSubject[0].identifier[*].value", "$.credentialSubject.identifier[*].value"], "filter": {"type": "string"}}
          ]
        }
      }]
    },
    "service_provider": {
      "id": "pd_sp",
      "format": {
        "jwt_vc": {"alg": ["ES256", "PS256", "RS256"]},
        "jwt_vp": {"alg": ["ES256", "PS256", "RS256"]}
      },
      "input_descriptors": [
        {
          "id": "id_sp",
          "constraints": {
            "fields": [
              {"path": ["$.type"], "filter": {"type": "string", "const": "ServiceProviderCredential"}}
            ]
          }
        },
        {
          "id": "id_sp_delegation",
          "constraints": {
            "fields": [
              {"path": ["$.type"], "filter": {"type": "string", "const": "ServiceProviderDelegationCredential"}},
              {"id": "delegating_hcp", "path": ["$.issuer"], "filter": {"type": "string"}},
              {"id": "delegating_hcp_ura", "path": ["$.credentialSubject[0].hasDelegation.delegatedBy.identifier[*].value", "$.credentialSubject.hasDelegation.delegatedBy.identifier[*].value"], "filter": {"type": "string"}}
            ]
          }
        }
      ]
    }
  }
}`

// provisionSubject creates a Nuts subject if it doesn't already exist and returns its first
// did:web. Idempotent across the test run.
func provisionSubject(t *testing.T, internalURL, subjectID string) string {
	t.Helper()
	resp, err := http.Get(internalURL + "/internal/vdr/v2/subject/" + subjectID)
	require.NoError(t, err)
	if resp.StatusCode == http.StatusOK {
		var dids []string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&dids))
		resp.Body.Close()
		for _, d := range dids {
			if strings.HasPrefix(d, "did:web:") {
				return d
			}
		}
		t.Fatalf("subject %s exists but has no did:web", subjectID)
	}
	resp.Body.Close()
	body, _ := json.Marshal(map[string]string{"subject": subjectID})
	resp, err = http.Post(internalURL+"/internal/vdr/v2/subject", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "create subject %s", subjectID)
	var created struct {
		Documents []struct {
			ID string `json:"id"`
		} `json:"documents"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.NotEmpty(t, created.Documents, "subject creation returned no DID documents")
	return created.Documents[0].ID
}

// issueAndLoad issues a credential against /internal/vcr/v2/issuer/vc and loads it into the
// holder wallet under the given subject. Both calls are routed through the same node.
func issueAndLoad(t *testing.T, internalURL, holderSubject string, body []byte) {
	t.Helper()
	resp, err := http.Post(internalURL+"/internal/vcr/v2/issuer/vc", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "issuer/vc failed: %s", respBody)
	loadResp, err := http.Post(internalURL+"/internal/vcr/v2/holder/"+holderSubject+"/vc", "application/json", bytes.NewReader(respBody))
	require.NoError(t, err)
	defer loadResp.Body.Close()
	loadBody, _ := io.ReadAll(loadResp.Body)
	require.True(t, loadResp.StatusCode >= 200 && loadResp.StatusCode < 300,
		"holder/%s/vc returned %d: %s", holderSubject, loadResp.StatusCode, loadBody)
}

func buildHCPCredential(issuerDID, subjectDID, ura string) []byte {
	body, _ := json.Marshal(map[string]any{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "HealthcareProviderCredential"},
		"issuer":   issuerDID,
		// expirationDate is required when withStatusList2021Revocation is not set; the
		// statuslist machinery would add network round-trips we don't need.
		"expirationDate": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":   subjectDID,
			"type": "HealthcareProvider",
			"identifier": []map[string]any{
				{"system": "http://fhir.nl/fhir/NamingSystem/ura", "value": ura},
			},
			"name": "Test HCP",
		},
		"format": "jwt_vc",
	})
	return body
}

func buildSPCredential(issuerDID, subjectDID string) []byte {
	body, _ := json.Marshal(map[string]any{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "ServiceProviderCredential"},
		"issuer":   issuerDID,
		// expirationDate is required when withStatusList2021Revocation is not set; the
		// statuslist machinery would add network round-trips we don't need.
		"expirationDate": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":   subjectDID,
			"type": "ServiceProvider",
			"name": "Test SP",
		},
		"format": "jwt_vc",
	})
	return body
}

func buildDelegationCredential(issuerDID, subjectDID, ura string) []byte {
	body, _ := json.Marshal(map[string]any{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "ServiceProviderDelegationCredential"},
		"issuer":   issuerDID,
		// expirationDate is required when withStatusList2021Revocation is not set; the
		// statuslist machinery would add network round-trips we don't need.
		"expirationDate": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":   subjectDID,
			"type": "ServiceProvider",
			"hasDelegation": map[string]any{
				"type": "Delegation",
				"delegatedBy": map[string]any{
					"type": "HealthcareProvider",
					"identifier": []map[string]any{
						{"system": "http://fhir.nl/fhir/NamingSystem/ura", "value": ura},
					},
				},
			},
		},
		"format": "jwt_vc",
	})
	return body
}

// mockAS is the httptest authorization server. It advertises jwt-bearer support and did:web in
// its metadata, captures the form body posted to /token, and returns a canned token response.
type mockAS struct {
	server   *httptest.Server
	captured atomic.Pointer[url.Values]
}

func newMockAS(t *testing.T) *mockAS {
	t.Helper()
	m := &mockAS{}
	mux := http.NewServeMux()
	// RFC 8414: for issuer `<host>/oauth2/<sp>`, the discovery URL is
	// `<host>/.well-known/oauth-authorization-server/oauth2/<sp>` (well-known is right after the host,
	// not at the end of the path).
	mux.HandleFunc("/.well-known/oauth-authorization-server/", func(w http.ResponseWriter, r *http.Request) {
		issuerPath := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-authorization-server")
		issuer := m.server.URL + issuerPath
		meta := map[string]any{
			"issuer":                   issuer,
			"token_endpoint":           issuer + "/token",
			"grant_types_supported":    []string{oauth.JwtBearerGrantType},
			"did_methods_supported":    []string{"web"},
			"vp_formats_supported":     map[string]any{"jwt_vp_json": map[string]any{"alg_values_supported": []string{"ES256"}}, "jwt_vc_json": map[string]any{"alg_values_supported": []string{"ES256"}}},
			"response_types_supported": []string{"code"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})
	mux.HandleFunc("/oauth2/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			require.NoError(t, r.ParseForm())
			form := r.PostForm
			m.captured.Store(&form)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token": "mock-token", "token_type": "Bearer", "expires_in": 900}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockAS) lastForm() url.Values {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f := m.captured.Load(); f != nil {
			return *f
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// verifyVP submits a JWT-VP to /internal/vcr/v2/verifier/vp and returns the parsed envelope. The
// validity field must be true; any failure aborts the test.
func verifyVP(t *testing.T, internalURL, vpJWT string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"verifiablePresentation": vpJWT,
	})
	resp, err := http.Post(internalURL+"/internal/vcr/v2/verifier/vp", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "verifier/vp returned %d: %s", resp.StatusCode, respBody)
	var result map[string]any
	require.NoError(t, json.Unmarshal(respBody, &result))
	require.True(t, jsonBool(t, result, "validity"), "verifier/vp returned validity=false: %s", respBody)
	return result
}

// pluckCredentialByType returns the first verifiable credential in the verifier response whose
// type list contains the requested type. The verifier's "credentials" array contains either
// parsed JSON objects (ldp_vc) or JWT strings (jwt_vc); for the latter we decode the payload to
// inspect the vc claim. Returns the parsed credential payload (the inner object for JWT VCs, or
// the entry itself for JSON-LD VCs).
func pluckCredentialByType(t *testing.T, vp map[string]any, credType string) map[string]any {
	t.Helper()
	creds, ok := vp["credentials"].([]any)
	require.True(t, ok, "verifier/vp response missing 'credentials' array")
	for _, c := range creds {
		var cm map[string]any
		switch v := c.(type) {
		case map[string]any:
			cm = v
		case string:
			cm = decodeJWTVCPayload(t, v)
		default:
			t.Fatalf("unsupported credential element type %T", c)
		}
		types, _ := cm["type"].([]any)
		for _, ty := range types {
			if s, _ := ty.(string); s == credType {
				return cm
			}
		}
	}
	t.Fatalf("no credential of type %q in verifier response", credType)
	return nil
}

// decodeJWTVCPayload decodes a JWT-encoded VerifiableCredential and returns the inner `vc` claim
// merged with the outer `iss` (-> issuer) and `sub` (-> credentialSubject.id) claims, matching the
// shape that ldp_vc credentials would return directly. Used to make assertions credential-format
// agnostic in the integration test.
func decodeJWTVCPayload(t *testing.T, jwtStr string) map[string]any {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3, "expected JWT with 3 parts, got %d", len(parts))
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "decode JWT payload")
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payloadBytes, &claims), "unmarshal JWT claims")
	vc, ok := claims["vc"].(map[string]any)
	require.True(t, ok, "JWT VC payload missing 'vc' claim")
	// Lift the JWT's iss into the VC's issuer field so callers can assert on it without caring
	// whether the credential is JWT-encoded or JSON-LD.
	if iss, ok := claims["iss"].(string); ok {
		if _, set := vc["issuer"]; !set {
			vc["issuer"] = iss
		}
	}
	return vc
}

func jsonBool(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key]
	require.True(t, ok, "key %q missing from response", key)
	b, ok := v.(bool)
	require.True(t, ok, "key %q is not bool: %T", key, v)
	return b
}

func jsonString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key]
	require.True(t, ok, "key %q missing", key)
	s, ok := v.(string)
	require.True(t, ok, "key %q is not string: %T", key, v)
	return s
}

// deepString walks the JSON value through the given keys (string for object keys, int for array
// indices) and returns the leaf as a string. Useful for asserting on nested credential subject
// structures returned by the verifier.
func deepString(t *testing.T, m any, keys ...any) string {
	t.Helper()
	for i, k := range keys {
		switch key := k.(type) {
		case string:
			obj, ok := m.(map[string]any)
			require.True(t, ok, "step %d (%v): expected object, got %T", i, key, m)
			m, ok = obj[key]
			require.True(t, ok, "step %d (%v): key not found", i, key)
		case int:
			arr, ok := m.([]any)
			require.True(t, ok, "step %d (%v): expected array, got %T", i, key, m)
			require.Less(t, key, len(arr), "step %d (%v): index out of range (len=%d)", i, key, len(arr))
			m = arr[key]
		default:
			t.Fatalf("step %d: unsupported key type %T", i, key)
		}
	}
	s, ok := m.(string)
	require.True(t, ok, "leaf is not string: %T (%v)", m, m)
	return s
}
