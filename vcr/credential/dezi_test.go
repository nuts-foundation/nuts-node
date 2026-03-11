package credential

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubbedRoundTripper is a test helper that returns a mock JWK Set for any HTTP request
type stubbedRoundTripper struct {
	keySets map[string]jwk.Set
}

func (s *stubbedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	keySet, ok := s.keySets[req.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "not found"}`))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	}

	// Marshal the key set to JSON
	jwksJSON, err := json.Marshal(keySet)
	if err != nil {
		return nil, err
	}

	// Return a mock HTTP response with the JWK Set
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(jwksJSON)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestCreateDeziIDToken(t *testing.T) {
	t.Run("version 0.7", func(t *testing.T) {
		const input = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMyNWRlOWFiLTQzMzAtNGMwMS04MjRlLWQ5YmQwYzM3Y2NhMCIsImprdSI6Imh0dHBzOi8vW2V4dGVybiBlbmRwb2ludF0vandrcy5qc29uIiwidHlwIjoiSldUIn0.eyJqdGkiOiI2MWIxZmFmYy00ZWM3LTQ0ODktYTI4MC04ZDBhNTBhM2Q1YTkiLCJpc3MiOiJhYm9ubmVlLmRlemkubmwiLCJleHAiOjE3NDAxMzExNzYsIm5iZiI6MTczMjE4MjM3NiwianNvbl9zY2hlbWEiOiJodHRwczovL3d3dy5kZXppLm5sL2pzb25fc2NoZW1hcy92ZXJrbGFyaW5nX3YxLmpzb24iLCJsb2FfZGV6aSI6Imh0dHA6Ly9laWRhcy5ldXJvcGUuZXUvTG9BL2hpZ2giLCJ2ZXJrbGFyaW5nX2lkIjoiODUzOWY3NWQtNjM0Yy00N2RiLWJiNDEtMjg3OTFkZmQxZjhkIiwiZGV6aV9udW1tZXIiOiIxMjM0NTY3ODkiLCJ2b29ybGV0dGVycyI6IkEuQi4iLCJ2b29ydm9lZ3NlbCI6bnVsbCwiYWNodGVybmFhbSI6IlpvcmdtZWRld2Vya2VyIiwiYWJvbm5lZV9udW1tZXIiOiI4NzY1NDMyMSIsImFib25uZWVfbmFhbSI6IlpvcmdhYW5iaWVkZXIiLCJyb2xfY29kZSI6IjAxLjAwMCIsInJvbF9uYWFtIjoiQXJ0cyIsInJvbF9jb2RlX2Jyb24iOiJodHRwOi8vd3d3LmRlemkubmwvcm9sX2NvZGVfYnJvbi9iaWciLCJyZXZvY2F0aWVfY29udHJvbGVfdXJpIjoiaHR0cHM6Ly9hdXRoLmRlemkubmwvcmV2b2NhdGllLXN0YXR1cy92MS92ZXJrbGFyaW5nLzg1MzlmNzVkLTYzNGMtNDdkYi1iYjQxLTI4NzkxZGZkMWY4ZCJ9.vegszRMWJjE-SBpfPO9lxN_fEY814ezsXRYhLXorPq3j_B_wlv4A92saasdEWrTALbl9Shux0i6JvkbouqvZ_oJpOUfJxWFGFfGGCuiMhiz4k1zm665i98e2xTqFzqjQySu_gup3wYm24FmnzbHxy02RzM3pXvQCsk_jIfQ1YcUZmNmXa5hR4DEn4Z9STLHd2HwyL6IKafEGl-R_kgbAnArSHQvuLw0Fpx62QD0tr5d3PbzPirBdkuy4G1l0umb69EjZMZ5MyIl8Y_irhQ9IFomAeSlU_zZp6UojVIOnCY2gL5EMc_8B1PDC6R_C--quGoh14jiSOJAeYSf_9ETjgQ"

		actual, err := CreateDeziIDTokenCredential(input)
		require.NoError(t, err)

		require.Len(t, actual.CredentialSubject, 1)
		subject := actual.CredentialSubject[0]
		employee := subject["employee"].(map[string]interface{})
		assert.Equal(t, "87654321", subject["identifier"])
		assert.Equal(t, "Zorgaanbieder", subject["name"])
		assert.Equal(t, "123456789", employee["identifier"])
		assert.Equal(t, "A.B.", employee["initials"])
		assert.Equal(t, "Zorgmedewerker", employee["surname"])
		assert.Equal(t, "", employee["surnamePrefix"]) // voorvoegsel is null in this token
		assert.Equal(t, []any{"01.000"}, employee["roles"])

		t.Run("from online test environment", func(t *testing.T) {
			// Payload:
			// {
			//  "json_schema": "https://www.dezi.nl/json_schemas/v1/verklaring.json",
			//  "loa_dezi": "http://eidas.europa.eu/LoA/high",
			//  "jti": "f410b255-6b07-4182-ac5c-c41f02bd3995",
			//  "verklaring_id": "0e970fcb-530c-482e-ba28-47b461d4dcb5",
			//  "dezi_nummer": "900022159",
			//  "voorletters": "J.",
			//  "voorvoegsel": null,
			//  "achternaam": "90017362",
			//  "abonnee_nummer": "90000380",
			//  "abonnee_naam": "Tést Zorginstelling 01",
			//  "rol_code": "92.000",
			//  "rol_naam": "Mondhygiënist",
			//  "rol_code_bron": "http://www.dezi.nl/rol_bron/big",
			//  "status_uri": "https://acceptatie.auth.dezi.nl/status/v1/verklaring/0e970fcb-530c-482e-ba28-47b461d4dcb5",
			//  "nbf": 1772665200,
			//  "exp": 1780610400,
			//  "iss": "https://abonnee.dezi.nl"
			//}
			const input = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFlNDY4MjlkLWM4ZTgtNDhhMC1iZDZhLTIxYjhhMDdiOGNiMiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYWNjZXB0YXRpZS5hdXRoLmRlemkubmwvZGV6aS9qd2tzLmpzb24ifQ.eyJqc29uX3NjaGVtYSI6Imh0dHBzOi8vd3d3LmRlemkubmwvanNvbl9zY2hlbWFzL3YxL3ZlcmtsYXJpbmcuanNvbiIsImxvYV9kZXppIjoiaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9Mb0EvaGlnaCIsImp0aSI6ImY0MTBiMjU1LTZiMDctNDE4Mi1hYzVjLWM0MWYwMmJkMzk5NSIsInZlcmtsYXJpbmdfaWQiOiIwZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJkZXppX251bW1lciI6IjkwMDAyMjE1OSIsInZvb3JsZXR0ZXJzIjoiSi4iLCJ2b29ydm9lZ3NlbCI6bnVsbCwiYWNodGVybmFhbSI6IjkwMDE3MzYyIiwiYWJvbm5lZV9udW1tZXIiOiI5MDAwMDM4MCIsImFib25uZWVfbmFhbSI6IlTDqXN0IFpvcmdpbnN0ZWxsaW5nIDAxIiwicm9sX2NvZGUiOiI5Mi4wMDAiLCJyb2xfbmFhbSI6Ik1vbmRoeWdpw6tuaXN0Iiwicm9sX2NvZGVfYnJvbiI6Imh0dHA6Ly93d3cuZGV6aS5ubC9yb2xfYnJvbi9iaWciLCJzdGF0dXNfdXJpIjoiaHR0cHM6Ly9hY2NlcHRhdGllLmF1dGguZGV6aS5ubC9zdGF0dXMvdjEvdmVya2xhcmluZy8wZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJuYmYiOjE3NzI2NjUyMDAsImV4cCI6MTc4MDYxMDQwMCwiaXNzIjoiaHR0cHM6Ly9hYm9ubmVlLmRlemkubmwifQ.ipR4stqmO8MOmmapukeQxIOVpwO_Ipjgy5BHjUsdCvuFObhVrj48AQCndtV48D_Ol1hXO4s9p4b-1epjEiobjEmEO0JQNU0BAOGG0eWl8MujfhzlDnmwo5AEtvdgTjlnBaLReVu1BJ8KYgc1DT7JhCukq9z5wZLqU1aqtETleX2-s-dNdTdwrUjJa1DvIgO-DQ_rCp-1tcfkr2rtyW16ztyI88Q2YdBkNGcG0if5aYZHpcQ4-121WBObUa0FhswS7EHni5Ru8KwZNq0HC8OLWw3YqLrYHTFe2K0GQjMtEO6zNxApbMXWKlgeWdf7Ry2rPpe2l9Z5NuMrFiB8JChZsQ"

			actual, err := CreateDeziIDTokenCredential(input)
			require.NoError(t, err)

			require.Len(t, actual.CredentialSubject, 1)
			subject := actual.CredentialSubject[0]
			employee := subject["employee"].(map[string]interface{})
			assert.Equal(t, "90000380", subject["identifier"])
			assert.Equal(t, "Tést Zorginstelling 01", subject["name"])
			assert.Equal(t, "900022159", employee["identifier"])
			assert.Equal(t, "J.", employee["initials"])
			assert.Equal(t, "90017362", employee["surname"])
			assert.Equal(t, "", employee["surnamePrefix"]) // voorvoegsel is null in this token
			assert.Equal(t, []any{"92.000"}, employee["roles"])
		})
	})
}

func TestDeziIDToken07CredentialValidator(t *testing.T) {
	iat := time.Unix(1732182376, 0)
	exp := time.Unix(1740131176, 0)
	validAt := time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)

	signingKeyCert, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
	require.NoError(t, err)

	publicKeyJWK, err := jwk.FromRaw(signingKeyCert.Leaf.PublicKey)
	require.NoError(t, err)
	require.NoError(t, publicKeyJWK.Set(jwk.KeyIDKey, "1"))
	correctKeySet := jwk.NewSet()
	require.NoError(t, correctKeySet.AddKey(publicKeyJWK))
	// KeySet taken from https://acceptatie.auth.dezi.nl/dezi/jwks.json, copied to make the test deterministic
	accKeySet := jwk.NewSet()
	err = json.Unmarshal([]byte(`{
  "keys" : [
  	{
  		"kty": "RSA",
  		"kid": "ae46829d-c8e8-48a0-bd6a-21b8a07b8cb2",
  		"x5c": [
    			"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"
  			],
  		"x5t": "mlPsZptNN2Bo8A8A6keBROJ6Q_U",
  		"x5t#S256": "UHZTsA9YMQnGRd24MZLxZabWczwuZn1PE9iV7j-oDm8",
  		"n": "4ObWRH19nPSyFsuKIQ_HG3FrlAqoBiij4mAYsAl7EWduHCGj92jkkGE4z6CNPgcdVK3J2WllhyKj7kDf1aZoCvfkVrQHpS_GnEBHME-5Vo3a8Z-1AfVxxSbVLlXFu793tx83U_mB8PVxHhzf6pW449fjZrSNc0cnluXoYRFgNGxD0hlL5JahMuOoWGpKJ5XVZp6bZjbIuHc2rC589THQl1N1V11QcpoCnQsFkX92JTtgtDl-jehrqr_P2-EXRhAZl59MAk6BAZXBJWDFY_gbjYW3j4q-ITBG5iGc8tYK3JxOCdK4K3Ql3QoNEptU32ET1zrRux5D5MRiC09MKoJ4bQ",
  		"e": "AQAB"
	}
]}`), &accKeySet)
	require.NoError(t, err)

	wrongKeySet := jwk.NewSet()
	wrongKey, _ := jwk.FromRaw([]byte("wrong-secret-key-data"))
	wrongKey.Set(jwk.KeyIDKey, "wrong-kid")
	wrongKeySet.AddKey(wrongKey)

	tests := []struct {
		name            string
		deziAttestation string
		keySet          jwk.Set
		modifyCred      func(*vc.VerifiableCredential)
		allowedJKU      []string
		wantErr         string
	}{
		{
			name:   "ok",
			keySet: correctKeySet,
		},
		{
			name:            "from test environment",
			deziAttestation: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFlNDY4MjlkLWM4ZTgtNDhhMC1iZDZhLTIxYjhhMDdiOGNiMiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYWNjZXB0YXRpZS5hdXRoLmRlemkubmwvZGV6aS9qd2tzLmpzb24ifQ.eyJqc29uX3NjaGVtYSI6Imh0dHBzOi8vd3d3LmRlemkubmwvanNvbl9zY2hlbWFzL3YxL3ZlcmtsYXJpbmcuanNvbiIsImxvYV9kZXppIjoiaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9Mb0EvaGlnaCIsImp0aSI6ImY0MTBiMjU1LTZiMDctNDE4Mi1hYzVjLWM0MWYwMmJkMzk5NSIsInZlcmtsYXJpbmdfaWQiOiIwZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJkZXppX251bW1lciI6IjkwMDAyMjE1OSIsInZvb3JsZXR0ZXJzIjoiSi4iLCJ2b29ydm9lZ3NlbCI6bnVsbCwiYWNodGVybmFhbSI6IjkwMDE3MzYyIiwiYWJvbm5lZV9udW1tZXIiOiI5MDAwMDM4MCIsImFib25uZWVfbmFhbSI6IlTDqXN0IFpvcmdpbnN0ZWxsaW5nIDAxIiwicm9sX2NvZGUiOiI5Mi4wMDAiLCJyb2xfbmFhbSI6Ik1vbmRoeWdpw6tuaXN0Iiwicm9sX2NvZGVfYnJvbiI6Imh0dHA6Ly93d3cuZGV6aS5ubC9yb2xfYnJvbi9iaWciLCJzdGF0dXNfdXJpIjoiaHR0cHM6Ly9hY2NlcHRhdGllLmF1dGguZGV6aS5ubC9zdGF0dXMvdjEvdmVya2xhcmluZy8wZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJuYmYiOjE3NzI2NjUyMDAsImV4cCI6MTc4MDYxMDQwMCwiaXNzIjoiaHR0cHM6Ly9hYm9ubmVlLmRlemkubmwifQ.ipR4stqmO8MOmmapukeQxIOVpwO_Ipjgy5BHjUsdCvuFObhVrj48AQCndtV48D_Ol1hXO4s9p4b-1epjEiobjEmEO0JQNU0BAOGG0eWl8MujfhzlDnmwo5AEtvdgTjlnBaLReVu1BJ8KYgc1DT7JhCukq9z5wZLqU1aqtETleX2-s-dNdTdwrUjJa1DvIgO-DQ_rCp-1tcfkr2rtyW16ztyI88Q2YdBkNGcG0if5aYZHpcQ4-121WBObUa0FhswS7EHni5Ru8KwZNq0HC8OLWw3YqLrYHTFe2K0GQjMtEO6zNxApbMXWKlgeWdf7Ry2rPpe2l9Z5NuMrFiB8JChZsQ",
		},
		{
			name:   "wrong exp",
			keySet: correctKeySet,
			modifyCred: func(c *vc.VerifiableCredential) {
				wrongExp := exp.Add(time.Hour)
				c.ExpirationDate = &wrongExp
			},
			wantErr: "'exp' does not match credential 'expirationDate'",
		},
		{
			name:   "wrong nbf",
			keySet: correctKeySet,
			modifyCred: func(c *vc.VerifiableCredential) {
				c.IssuanceDate = iat.Add(-time.Hour)
			},
			wantErr: "'nbf' does not match credential 'issuanceDate'",
		},
		{
			name:    "invalid signature",
			keySet:  wrongKeySet,
			wantErr: "failed to verify JWT signature",
		},
		{
			name:    "JWK set endpoint unreachable",
			keySet:  nil,
			wantErr: "failed to verify JWT signature",
		},
		{
			name:   "token claims differ from credential subject",
			keySet: correctKeySet,
			modifyCred: func(c *vc.VerifiableCredential) {
				c.CredentialSubject[0]["identifier"] = "different-identifier"
			},
			wantErr: "credential subject does not match id_token claims",
		},
		{
			name:       "JKU not allowed",
			allowedJKU: []string{"https://example.com/other"},
			wantErr:    "rejected by whitelist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deziAttestation := tt.deziAttestation
			if tt.deziAttestation == "" {
				tokenBytes, err := CreateTestDezi07IDToken(iat, exp, signingKeyCert.PrivateKey)
				require.NoError(t, err)
				deziAttestation = string(tokenBytes)
			}

			cred, err := CreateDeziIDTokenCredential(deziAttestation)
			require.NoError(t, err)

			if tt.modifyCred != nil {
				tt.modifyCred(cred)
			}

			validator := deziIDToken07CredentialValidator{
				clock: func() time.Time { return validAt },
				httpClient: &http.Client{Transport: &stubbedRoundTripper{keySets: map[string]jwk.Set{
					"https://acceptatie.auth.dezi.nl/dezi/jwks.json": accKeySet,
					"https://example.com/jwks.json":                  tt.keySet,
				}}},
				allowedJKU: []string{
					"https://acceptatie.auth.dezi.nl/dezi/jwks.json",
					"https://example.com/jwks.json",
				},
			}
			if tt.allowedJKU != nil {
				validator.allowedJKU = tt.allowedJKU
			}

			err = validator.Validate(*cred)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeziIDToken2024CredentialValidator(t *testing.T) {
	t.Skip("TODO: implement or remove")
	const exampleToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjFNY2p3cjgxMGpOVUZHVHR6T21MeTRTNnN5cVJ1aVZ1YVM0UmZyWmZwOEk9IiwieDV0Ijoibk4xTVdBeFRZTUgxOE45cFBWMlVIYlVZVDVOWTByT19TaHQyLWZVWF9nOCJ9.eyJhdWQiOiIwMDZmYmYzNC1hODBiLTRjODEtYjZlOS01OTM2MDA2NzVmYjIiLCJleHAiOjE3MDE5MzM2OTcsImluaXRpYWxzIjoiQi5CLiIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0OjgwMDYiLCJqc29uX3NjaGVtYSI6Imh0dHBzOi8vbG9jYWxob3N0OjgwMDYvanNvbl9zY2hlbWEuanNvbiIsImxvYV9hdXRobiI6Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvTG9BL2hpZ2giLCJsb2FfdXppIjoiaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9Mb0EvaGlnaCIsIm5iZiI6MTcwMTkzMzYyNywicmVsYXRpb25zIjpbeyJlbnRpdHlfbmFtZSI6IlpvcmdhYW5iaWVkZXIiLCJyb2xlcyI6WyIwMS4wNDEiLCIzMC4wMDAiLCIwMS4wMTAiLCIwMS4wMTEiXSwidXJhIjoiODc2NTQzMjEifV0sInN1cm5hbWUiOiJKYW5zZW4iLCJzdXJuYW1lX3ByZWZpeCI6InZhbiBkZXIiLCJ1emlfaWQiOiI5MDAwMDAwMDkiLCJ4NWMiOiJNSUlEMWpDQ0FiNENDUUQwRmx2SnNiY3J2VEFOQmdrcWhraUc5dzBCQVFzRkFEQW9NUXN3Q1FZRFZRUUREQUpWXG5VekVaTUJjR0ExVUVBd3dRYVc1blpTMDJMWFY2YVhCdll5MWpZVEFlRncweU16RXlNREV4TWpNek16QmFGdzB5XG5OVEEwTVRReE1qTXpNekJhTURJeEN6QUpCZ05WQkFZVEFsVlRNU013SVFZRFZRUUREQnB1YkMxMWVtbHdiMk10XG5jR2h3TFd4aGNtRjJaV3d0WkdWdGJ6Q0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCXG5BS2JDQ0dZYTcwL0VlS2dwc0N0QnRHUmlIWVJyb2RWQWN0bHJPTUhFZDI2aGpSdmN0TGZOaXl0MFF5QkZsekN2XG4wVkRYUjc3OWVvU1E2bWdPYURjNzFrYi9zR1dxbjhMZFE3NEp0WTVnSTVxRzduM1JYM0VRWkxFdGIxNmp6WWROXG5LMU5mMm9GK0tNV2t2eWMvVjlSNWUyNjdyTjJpUklHQlNKUTFmZmN4RHFUZnJNVmxjaFYyZmdWVDdZTzQ3U25qXG5MMXdDK0Z4cXhTRzc1N056OHlleVBncjJaazFvaWF6dHhQY1hXRlVpTklGWm9KUzlpVzdITTZyQ204WjcvbVJjXG40Qm5kbC9wbkZlMjVrZmhPZzlKSVVNbzFvcjltbDZDSXN6Um9aL2hTOHZCOUduNldUS05CYUgxMTB6Sno4eXNkXG42cXM4WkpCYURia0pnSTZMNlZtL3d0OENBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQWl6eEJmYUFhXG5ETlFOOWhYS0ZKZVB6N2RUUEx3SFkvWmpDNDlkUXJ0eVd6ZmdyMUxLaTRvMWl4amtkZzJGWFU5dCt4TXVXZ3hYXG5GZGJqT0pMZGNRWVdFWWIrVzdLbWtnbEljUDhiT2tSRFdmcGxnc2twYVRvZ1JLMDk1UzFDdU1NOXYwYktDL3RzXG5kSGIzVWZxVzRVNFprbzM4L1VlOWZSRjhyYTJwNzFRRnM4K250L0JBd0NrenJOTHpheE1ZOC8vVGlGVStaRVlMXG56UElRQmpLYVlCOHlWaDBXaDNxYWllQjJCektVYW4rRXlzaDJiVWM5VHBsUXlrSWRrNHo2VCtGTzVLVGo1ZVZrXG42enBIZmxXV0NUNjF5MTVtdTN4QUViODNyT2YrekZwb05HaURzc2lrbzBPZUxLN0ZscWg3SHVDUDI2Tk5ud3NiXG5WR3drZzYwcER1K0FTRzJhbTNUUGlmM0pwSTdza3pBQkZ3NHZidlBVcElrNkltM3ljQzk4R3lYb3dRdWpJMFpUXG4xNmRYZmgxRTM4cHNSVWVPNW8rdXhZNk1VUFhOU2lvWVowbWYzQkFSTGFoTjQxcnF4S1h6NU1MMURTWm5JT1pLXG5GM3BlU2dnYVpvUmkxaDByNlcxNFdFY1l2eGRIRGtWUjZNMXFXMGk3WWVJQms2a2FYRWt3Q21GejNoazV3OWFuXG5XSkRqbk1xU1JnUnNGVmNJTC9FemkvRWx1YmsyMWY0TEhURVFtc2p6emQxRytkMDlmamRJNkpyaFlNZnRHdVlaXG40ak9aWldwem9NSDFUaVpaK0prQmR5UndFZGJxelcrdisvMEJaUXk2SFJhWmxvbWJjT21TOU1TakZSRFR5VUdXXG5EOUYxZVVJcUtjdDB5eUpQUFhIM2xEa3pxcXRYNERMY29wbz0ifQ.VvzIXZ8FCIwxvP3Wc4kLvIgQChJZAhS-DcKKvkiZg677w-ZRciIFCWUH5oXLqG-emyV4f87tIoWnp4TY3gGFNljNrtlTVCv3zXaTCxHwzL6q2QCs1liBus2uPv0kjBtzeve2G5_Owst3ndeUcwLJPnTIoYRLvbjjaPkFTg49K5ZTpN8E9dl7Gimwgv_rZ1fOH7XrAwlTY-jF34wsR_K17wHI5Zp237_HcAPqnMI8P3U7u74Vu-3mqCePubVBDnT4bGcd4flZCFH-LTDhew9BO4cBkBxafAev7OB5A9qGOKEtRynTDAOkazyb8_qwJAGnyCAVxBQ4VFRB1-cE576TLQ`
	const exampleCertificateDERBase64 = `MIID1jCCAb4CCQD0FlvJsbcrvTANBgkqhkiG9w0BAQsFADAoMQswCQYDVQQDDAJV
UzEZMBcGA1UEAwwQaW5nZS02LXV6aXBvYy1jYTAeFw0yMzEyMDExMjMzMzBaFw0y
NTA0MTQxMjMzMzBaMDIxCzAJBgNVBAYTAlVTMSMwIQYDVQQDDBpubC11emlwb2Mt
cGhwLWxhcmF2ZWwtZGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKbCCGYa70/EeKgpsCtBtGRiHYRrodVActlrOMHEd26hjRvctLfNiyt0QyBFlzCv
0VDXR779eoSQ6mgOaDc71kb/sGWqn8LdQ74JtY5gI5qG7n3RX3EQZLEtb16jzYdN
K1Nf2oF+KMWkvyc/V9R5e267rN2iRIGBSJQ1ffcxDqTfrMVlchV2fgVT7YO47Snj
L1wC+FxqxSG757Nz8yeyPgr2Zk1oiaztxPcXWFUiNIFZoJS9iW7HM6rCm8Z7/mRc
4Bndl/pnFe25kfhOg9JIUMo1or9ml6CIszRoZ/hS8vB9Gn6WTKNBaH110zJz8ysd
6qs8ZJBaDbkJgI6L6Vm/wt8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAizxBfaAa
DNQN9hXKFJePz7dTPLwHY/ZjC49dQrtyWzfgr1LKi4o1ixjkdg2FXU9t+xMuWgxX
FdbjOJLdcQYWEYb+W7KmkglIcP8bOkRDWfplgskpaTogRK095S1CuMM9v0bKC/ts
dHb3UfqW4U4Zko38/Ue9fRF8ra2p71QFs8+nt/BAwCkzrNLzaxMY8//TiFU+ZEYL
zPIQBjKaYB8yVh0Wh3qaieB2BzKUan+Eysh2bUc9TplQykIdk4z6T+FO5KTj5eVk
6zpHflWWCT61y15mu3xAEb83rOf+zFpoNGiDssiko0OeLK7Flqh7HuCP26NNnwsb
VGwkg60pDu+ASG2am3TPif3JpI7skzABFw4vbvPUpIk6Im3ycC98GyXowQujI0ZT
16dXfh1E38psRUeO5o+uxY6MUPXNSioYZ0mf3BARLahN41rqxKXz5ML1DSZnIOZK
F3peSggaZoRi1h0r6W14WEcYvxdHDkVR6M1qW0i7YeIBk6kaXEkwCmFz3hk5w9an
WJDjnMqSRgRsFVcIL/Ezi/Elubk21f4LHTEQmsjzzd1G+d09fjdI6JrhYMftGuYZ
4jOZZWpzoMH1TiZZ+JkBdyRwEdbqzW+v+/0BZQy6HRaZlombcOmS9MSjFRDTyUGW
D9F1eUIqKct0yyJPPXH3lDkzqqtX4DLcopo=`
	certificateDER, err := base64.StdEncoding.DecodeString(exampleCertificateDERBase64)
	require.NoError(t, err)
	exampleCertificate, err := x509.ParseCertificate(certificateDER)
	require.NoError(t, err)
	// Setup trust store with the Dezi certificate as root CA
	exampleTrustStore := core.BuildTrustStore([]*x509.Certificate{})
	exampleTrustStore.RootCAs = append(exampleTrustStore.RootCAs, exampleCertificate)

	// Load a signing key pair for creating test tokens
	// Note: In real scenarios, the signing key would match the cert in x5c
	signingKeyCert, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
	require.NoError(t, err)
	signingKeyCert.Leaf, err = x509.ParseCertificate(signingKeyCert.Certificate[0])
	require.NoError(t, err)
	trustStore := core.BuildTrustStore([]*x509.Certificate{})
	trustStore.RootCAs = append(trustStore.RootCAs, signingKeyCert.Leaf)

	// Use a validation time within the Dezi certificate validity period
	validAt := time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)

	// createToken returns a factory function that creates a JWT with the given x5c value
	// If x5cValue is a *x509.Certificate, it encodes that certificate in x5c
	// If x5cValue is any other type (string, []string, nil), it's used directly as the x5c claim
	createToken := func(x5cValue any, nbf *time.Time, exp *time.Time) func(t *testing.T) []byte {
		if nbf == nil {
			nbf = new(time.Time)
			*nbf = time.Unix(1732182376, 0) // Nov 21, 2024
		}
		if exp == nil {
			exp = new(time.Time)
			*exp = time.Unix(1740131176, 0) // Feb 21, 2025
		}
		return func(t *testing.T) []byte {
			token := jwt.New()
			claims := map[string]any{
				jwt.AudienceKey:   "006fbf34-a80b-4c81-b6e9-593600675fb2",
				jwt.ExpirationKey: exp.Unix(),
				jwt.NotBeforeKey:  nbf.Unix(),
				jwt.IssuerKey:     "https://max.proeftuin.Dezi-online.rdobeheer.nl",
				jwt.JwtIDKey:      "test-jwt-id",
				"dezi_nummer":     "900000009",
				"initials":        "B.B.",
				"surname":         "Jansen",
				"surname_prefix":  "van der",
				"relations": []map[string]interface{}{
					{"entity_name": "Zorgaanbieder", "roles": []string{"01.041"}, "ura": "87654321"},
				},
			}

			// Handle x5c based on type
			if cert, ok := x5cValue.(*x509.Certificate); ok {
				// Encode the provided certificate in x5c
				x5cArray := []string{base64.StdEncoding.EncodeToString(cert.Raw)}
				claims["x5c"] = x5cArray
			} else if x5cValue != nil {
				// Use x5cValue directly (for testing invalid formats)
				claims["x5c"] = x5cValue
			}
			// If x5cValue is nil, don't add x5c claim (for testing missing x5c)

			for k, v := range claims {
				require.NoError(t, token.Set(k, v))
			}
			signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKeyCert.PrivateKey))
			require.NoError(t, err)
			return signed
		}
	}

	tests := []struct {
		name        string
		createToken func(t *testing.T) []byte
		modifyCred  func(*vc.VerifiableCredential)
		trustStore  *core.TrustStore
		wantErr     string
	}{
		{
			name: "ok",
			createToken: func(t *testing.T) []byte {
				return []byte(exampleToken)
			},
			trustStore: exampleTrustStore,
		},
		{
			name:        "missing x5c",
			createToken: createToken(nil, nil, nil),
			wantErr:     "missing 'x5c' claim",
		},
		{
			name:        "invalid certificate",
			createToken: createToken([]string{"invalid-base64!!!"}, nil, nil),
			wantErr:     "decode 'x5c",
		},
		{
			name:        "credential's nbf does not match token's nbf",
			createToken: createToken([]string{base64.StdEncoding.EncodeToString(signingKeyCert.Leaf.Raw)}, nil, nil),
			modifyCred: func(c *vc.VerifiableCredential) {
				c.IssuanceDate = time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
			},
			wantErr: "'nbf' does not match credential 'issuanceDate'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenBytes := tt.createToken(t)
			cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
			require.NoError(t, err)

			if tt.modifyCred != nil {
				tt.modifyCred(cred)
			}
			validator := deziIDToken2024CredentialValidator{
				clock:      func() time.Time { return validAt },
				trustStore: trustStore,
			}
			if tt.trustStore != nil {
				validator.trustStore = tt.trustStore
			}

			err = validator.Validate(*cred)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
