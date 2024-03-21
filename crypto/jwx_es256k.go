//go:build jwx_es256k

package crypto

import "github.com/lestrrat-go/jwx/v2/jwa"

func init() {
	AddSupportedAlgorithm(jwa.ES256K)
}
