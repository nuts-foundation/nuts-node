package credential

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubbedRoundTripper is a test helper that returns a mock JWK Set for any HTTP request
type stubbedRoundTripper struct {
	keySet jwk.Set
}

func (s *stubbedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Marshal the key set to JSON
	jwksJSON, err := json.Marshal(s.keySet)
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

	// Load signing key, create JWK set
	signingKeyCert, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
	require.NoError(t, err)
	signingKey := signingKeyCert.PrivateKey
	signingKeyJWK, err := jwk.FromRaw(signingKey)
	require.NoError(t, err)
	require.NoError(t, signingKeyJWK.Set(jwk.KeyIDKey, "1"))

	// Create JWK set with the public key
	publicKeyJWK, err := jwk.FromRaw(signingKeyCert.Leaf.PublicKey)
	require.NoError(t, err)
	require.NoError(t, publicKeyJWK.Set(jwk.KeyIDKey, "1"))
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKeyJWK))

	validator := deziIDTokenCredentialValidator{
		clock: func() time.Time {
			return validAt
		},
		httpClient: &http.Client{
			Transport: &stubbedRoundTripper{keySet: keySet},
		},
	}

	t.Run("ok", func(t *testing.T) {
		tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKey)
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
		require.NoError(t, err)

		err = validator.Validate(*cred)
		require.NoError(t, err)
	})

	t.Run("error - wrong exp", func(t *testing.T) {
		tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKey)
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
		require.NoError(t, err)

		// Modify credential expiration to be different from token
		wrongExp := exp.Add(time.Hour)
		cred.ExpirationDate = &wrongExp

		err = validator.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "'exp' does not match credential 'expirationDate'")
	})

	t.Run("error - wrong nbf", func(t *testing.T) {
		tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKey)
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
		require.NoError(t, err)

		// Modify credential issuance date to be different from token
		wrongNbf := iat.Add(-time.Hour)
		cred.IssuanceDate = wrongNbf

		err = validator.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "'nbf' does not match credential 'issuanceDate'")
	})

	t.Run("error - invalid signature (wrong key in JWK set)", func(t *testing.T) {
		// Create a different key set (wrong keys)
		wrongKeySet := jwk.NewSet()
		wrongKey, _ := jwk.FromRaw([]byte("wrong-secret-key-data"))
		kid := "wrong-kid"
		wrongKey.Set(jwk.KeyIDKey, kid)
		wrongKeySet.AddKey(wrongKey)

		validatorWithWrongKeys := deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: &http.Client{
				Transport: &stubbedRoundTripper{keySet: wrongKeySet},
			},
		}

		tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKey)
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
		require.NoError(t, err)

		err = validatorWithWrongKeys.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify JWT signature")
	})

	t.Run("error - jku endpoint unreachable", func(t *testing.T) {
		// Use HTTP client that returns an error for any request
		validatorWithBrokenClient := deziIDTokenCredentialValidator{
			clock: func() time.Time {
				return validAt
			},
			httpClient: &http.Client{
				Transport: &stubbedRoundTripper{keySet: nil}, // Will fail when trying to marshal nil
			},
		}

		tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKey)
		require.NoError(t, err)

		cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
		require.NoError(t, err)

		err = validatorWithBrokenClient.Validate(*cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify JWT signature")
	})
}
