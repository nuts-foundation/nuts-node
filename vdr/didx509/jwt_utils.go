package didx509

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExtractProtectedHeaders(jwt string) (map[string]interface{}, error) {
	message, _ := jws.ParseString(jwt)
	headers := make(map[string]interface{})
	var err error
	if message != nil && len(message.Signatures()) > 0 {
		headers, err = message.Signatures()[0].ProtectedHeaders().AsMap(context.Background())
		if err != nil {
			return nil, err
		}
	}
	return headers, nil
}
