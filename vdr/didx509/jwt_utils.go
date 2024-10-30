package didx509

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jws"
)

var (
	ErrorInvalidNumberOfSignatures = errors.New("invalid number of signatures")
)

// ExtractProtectedHeaders extracts the protected headers from a JWT string.
// The function takes a JWT string as input and returns a map of the protected headers.
// Note that:
//   - This method ignores any parsing errors and returns an empty map instead of an error.
func ExtractProtectedHeaders(jwt string) (map[string]interface{}, error) {
	headers := make(map[string]interface{})
	if jwt != "" {
		message, _ := jws.ParseString(jwt)
		if message != nil {
			if len(message.Signatures()) != 1 {
				return nil, ErrorInvalidNumberOfSignatures
			}
			var err error
			headers, err = message.Signatures()[0].ProtectedHeaders().AsMap(context.Background())
			if err != nil {
				return nil, err
			}
		}
	}
	return headers, nil
}
