//go:build jwx_es256k

package oauth

import "github.com/lestrrat-go/jwx/v2/jwa"

func init() {
	algValuesSupported = append(algValuesSupported, jwa.ES256K.String())
}
