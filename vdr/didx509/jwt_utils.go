package didx509

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jws"
	"strings"
)

// ExtractProtectedHeaders extracts the protected headers from a JWT string.
// The function takes a JWT string as input and returns a map of the protected headers.
// Note that:
//   - This method ignores strings that don't look like JWTs and returns an empty map.
//   - This method ignores any parsing errors and returns an empty map instead of an error.
func ExtractProtectedHeaders(jwt string) (map[string]interface{}, error) {
	headers := make(map[string]interface{})
	if jwt != "" && strings.Count(jwt, ".") > 1 && strings.HasPrefix(jwt, "ey") {
		message, _ := jws.ParseString(jwt)
		if message != nil && len(message.Signatures()) > 0 {
			var err error
			headers, err = message.Signatures()[0].ProtectedHeaders().AsMap(context.Background())
			if err != nil {
				return nil, err
			}
		}
	}
	return headers, nil
}
