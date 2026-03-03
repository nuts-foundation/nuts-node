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
	})
	t.Run("version 2024", func(t *testing.T) {

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

	wrongKeySet := jwk.NewSet()
	wrongKey, _ := jwk.FromRaw([]byte("wrong-secret-key-data"))
	wrongKey.Set(jwk.KeyIDKey, "wrong-kid")
	wrongKeySet.AddKey(wrongKey)

	tests := []struct {
		name       string
		keySet     jwk.Set
		modifyCred func(*vc.VerifiableCredential)
		wantErr    string
	}{
		{
			name:   "ok",
			keySet: correctKeySet,
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
			name:    "jku endpoint unreachable",
			keySet:  nil,
			wantErr: "failed to verify JWT signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenBytes, err := CreateTestDeziIDToken(iat, exp, signingKeyCert.PrivateKey)
			require.NoError(t, err)

			cred, err := CreateDeziIDTokenCredential(string(tokenBytes))
			require.NoError(t, err)

			if tt.modifyCred != nil {
				tt.modifyCred(cred)
			}

			validator := deziIDToken07CredentialValidator{
				clock:      func() time.Time { return validAt },
				httpClient: &http.Client{Transport: &stubbedRoundTripper{keySet: tt.keySet}},
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
				"uzi_id":          "900000009",
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
			name:        "credential's exp does not match token's exp",
			createToken: createToken([]string{base64.StdEncoding.EncodeToString(signingKeyCert.Leaf.Raw)}, nil, nil),
			modifyCred: func(c *vc.VerifiableCredential) {
				wrongExp := exp.Add(time.Hour)
				c.ExpirationDate = &wrongExp
			},
			wantErr: "'exp' does not match credential 'expirationDate'",
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
