package credential

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDeziIDToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
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
	})
}

func TestDeziIDTokenCredentialValidator(t *testing.T) {
	// Test constants
	iat := time.Unix(1732182376, 0) // Nov 21, 2024
	exp := time.Unix(1740131176, 0) // Feb 21, 2025
	validAt := time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)

	// Helper to create token with mocked JWK server
	createTokenWithMockServer := func(t *testing.T, keySet jwk.Set) (string, *httptest.Server) {
		// Create test token
		tokenBytes, err := CreateTestDeziIDToken(iat, exp)
		require.NoError(t, err)

		// Create mock HTTPS server (jku must be HTTPS)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(keySet)
		}))

		// Parse token and update jku header
		msg, err := jws.Parse(tokenBytes)
		require.NoError(t, err)

		sig := msg.Signatures()[0]
		headers := jws.NewHeaders()
		for iter := sig.ProtectedHeaders().Iterate(context.Background()); iter.Next(context.Background()); {
			pair := iter.Pair()
			headers.Set(pair.Key.(string), pair.Value)
		}
		headers.Set("jku", server.URL+"/jwks.json")

		// Load key for re-signing
		keyPair, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
		require.NoError(t, err)
		privateKey, err := jwk.FromRaw(keyPair.PrivateKey)
		require.NoError(t, err)

		// Parse original token claims
		origToken, err := jwt.Parse(tokenBytes, jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err)

		// Re-sign with new headers
		signedToken, err := jwt.Sign(origToken, jwt.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)

		return string(signedToken), server
	}

	// Helper to extract JWK set from token
	extractJWKSet := func(t *testing.T) jwk.Set {
		tokenBytes, err := CreateTestDeziIDToken(iat, exp)
		require.NoError(t, err)

		token, err := jwt.Parse(tokenBytes, jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err)

		jwksRaw, ok := token.Get("jwks")
		require.True(t, ok)

		jwksJSON, err := json.Marshal(jwksRaw)
		require.NoError(t, err)

		keySet, err := jwk.Parse(jwksJSON)
		require.NoError(t, err)

		return keySet
	}

	t.Run("ok - valid signature and timestamps", func(t *testing.T) {
		keySet := extractJWKSet(t)
		tokenStr, server := createTokenWithMockServer(t, keySet)
		defer server.Close()

		cred, err := CreateDeziIDTokenCredential(tokenStr)
		require.NoError(t, err)

		err = deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: server.Client(), // Use test server's client to trust its certificate
		}.Validate(*cred)
		require.NoError(t, err)
	})

	t.Run("error - wrong exp", func(t *testing.T) {
		keySet := extractJWKSet(t)
		tokenStr, server := createTokenWithMockServer(t, keySet)
		defer server.Close()

		cred, err := CreateDeziIDTokenCredential(tokenStr)
		require.NoError(t, err)

		// Modify credential expiration to be different from token
		wrongExp := exp.Add(time.Hour)
		cred.ExpirationDate = &wrongExp

		err = deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: server.Client(),
		}.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "'exp' does not match credential 'expirationDate'")
	})

	t.Run("error - wrong nbf", func(t *testing.T) {
		keySet := extractJWKSet(t)
		tokenStr, server := createTokenWithMockServer(t, keySet)
		defer server.Close()

		cred, err := CreateDeziIDTokenCredential(tokenStr)
		require.NoError(t, err)

		// Modify credential issuance date to be different from token
		wrongNbf := iat.Add(-time.Hour)
		cred.IssuanceDate = wrongNbf

		err = deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: server.Client(),
		}.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "'nbf' does not match credential 'issuanceDate'")
	})

	t.Run("error - invalid signature (wrong key in JWK set)", func(t *testing.T) {
		// Create a different key set (wrong keys)
		wrongKeySet := jwk.NewSet()
		wrongKey, _ := jwk.FromRaw([]byte("wrong-secret-key-data"))
		x5t := sha1.Sum([]byte("wrong-cert"))
		kid := base64.StdEncoding.EncodeToString(x5t[:])
		wrongKey.Set(jwk.KeyIDKey, kid)
		wrongKeySet.AddKey(wrongKey)

		tokenStr, server := createTokenWithMockServer(t, wrongKeySet)
		defer server.Close()

		cred, err := CreateDeziIDTokenCredential(tokenStr)
		require.NoError(t, err)

		err = deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: server.Client(),
		}.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify JWT signature")
	})

	t.Run("error - jku endpoint unreachable", func(t *testing.T) {
		// Create token bytes
		tokenBytes, err := CreateTestDeziIDToken(iat, exp)
		require.NoError(t, err)

		// Parse and update jku to non-existent endpoint
		msg, err := jws.Parse(tokenBytes)
		require.NoError(t, err)

		sig := msg.Signatures()[0]
		headers := jws.NewHeaders()
		for iter := sig.ProtectedHeaders().Iterate(context.Background()); iter.Next(context.Background()); {
			pair := iter.Pair()
			headers.Set(pair.Key.(string), pair.Value)
		}
		headers.Set("jku", "https://localhost:9999/jwks.json")

		keyPair, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
		require.NoError(t, err)
		privateKey, err := jwk.FromRaw(keyPair.PrivateKey)
		require.NoError(t, err)

		origToken, err := jwt.Parse(tokenBytes, jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err)

		signedToken, err := jwt.Sign(origToken, jwt.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(signedToken))
		require.NoError(t, err)

		err = deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
		}.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify JWT signature")
	})
}
