package didx509

import (
	"testing"
)

func TestExtractProtectedHeaders(t *testing.T) {
	testCases := []struct {
		name          string
		jwt           string
		expectResults bool
	}{
		{
			name:          "ValidJWT",
			jwt:           "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectResults: true,
		},
		{
			name:          "InvalidJWTHeader",
			jwt:           "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsIng1YyI6dHJ1ZX0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fyenaNFjX705H02aOrpHayRVHa1uVxpQRUxWCl91rB4",
			expectResults: false,
		},
		{
			name:          "InvalidJWT",
			jwt:           "invalidToken",
			expectResults: false,
		},
		{
			name:          "EmptyJWT",
			jwt:           "",
			expectResults: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers, err := ExtractProtectedHeaders(tc.jwt)
			if err != nil {
				t.Errorf("ExtractProtectedHeaders() error = %v", err)
				return
			}
			if err == nil {
				if !tc.expectResults && len(headers) > 0 {
					t.Errorf("ExtractProtectedHeaders() = %v, expected an empty header map", headers)
				} else if tc.expectResults {
					if _, ok := headers["alg"]; ok == false {
						t.Errorf("ExtractProtectedHeaders() = %v, expected a valid header map", headers)
					}
					if _, ok := headers["typ"]; ok == false {
						t.Errorf("ExtractProtectedHeaders() = %v, expected a valid header map", headers)
					}
				}
			}
		})
	}
}
