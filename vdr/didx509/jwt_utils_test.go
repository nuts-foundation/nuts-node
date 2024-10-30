package didx509

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nuts-foundation/nuts-node/crypto"
	"testing"
)

func TestExtractProtectedHeaders(t *testing.T) {
	jwt, err := normalJws(map[string]interface{}{"iss": "test"})
	if err != nil {
		t.Error(err)
	}
	double, err := doubleSignedJws(map[string]interface{}{"iss": "test"})
	if err != nil {
		t.Error(err)
	}
	none, err := noSignedJws(map[string]interface{}{"iss": "test"})
	if err != nil {
		t.Error(err)
	}
	testCases := []struct {
		name          string
		jwt           string
		expectResults bool
		expectError   error
	}{
		{
			name:          "ValidJWT",
			jwt:           jwt,
			expectResults: true,
		},
		{
			name:          "too many signatures",
			jwt:           double,
			expectResults: false,
			expectError:   ErrorInvalidNumberOfSignatures,
		},
		{
			name:          "no signatures",
			jwt:           none,
			expectResults: true,
		},
		{
			name: "InvalidJWTHeader",
			jwt:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsIng1YyI6dHJ1ZX0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fyenaNFjX705H02aOrpHayRVHa1uVxpQRUxWCl91rB4",
		},
		{
			name: "InvalidJWT",
			jwt:  "invalidToken",
		},
		{
			name: "EmptyJWT",
			jwt:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers, err := ExtractProtectedHeaders(tc.jwt)
			if err != nil {
				if tc.expectError == nil {
					t.Errorf("ExtractProtectedHeaders() error = %v", err)
				} else if err.Error() != tc.expectError.Error() {
					t.Errorf("ExtractProtectedHeaders() error = %v, expected: %v", err, tc.expectError)
				}
			} else {
				if !tc.expectResults && len(headers) > 0 {
					t.Errorf("ExtractProtectedHeaders() = %v, expected an empty header map", headers)
				} else if tc.expectResults {
					if _, ok := headers["alg"]; ok == false {
						t.Errorf("ExtractProtectedHeaders() = %v, expected a valid header map", headers)
					}
				}
			}
		})
	}
}

func normalJws(claims map[string]interface{}) (string, error) {
	jwk, err := crypto.GenerateJWK()
	if err != nil {
		return "", err
	}
	marshal, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sign, err := jws.Sign(marshal, jws.WithKey(jwa.ES256, jwk))
	if err != nil {
		return "", err
	}
	return string(sign), err
}
func doubleSignedJws(claims map[string]interface{}) (string, error) {
	jwk, err := crypto.GenerateJWK()
	if err != nil {
		return "", err
	}
	marshal, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sign, err := jws.Sign(marshal, jws.WithKey(jwa.ES256, jwk), jws.WithKey(jwa.ES256, jwk), jws.WithJSON())
	if err != nil {
		return "", err
	}
	return string(sign), err
}
func noSignedJws(claims map[string]interface{}) (string, error) {
	marshal, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sign, err := jws.Sign(marshal, jws.WithInsecureNoSignature())
	if err != nil {
		return "", err
	}
	return string(sign), err
}
