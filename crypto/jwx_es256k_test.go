//go:build jwx_es256k
// +build jwx_es256k

package crypto

import (
	"crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestES256k(t *testing.T) {
	t.Run("test ES256K", func(t *testing.T) {
		ecKey := test.GenerateECKey()
		token := jwt.New()
		signature, _ := jwt.Sign(token, jwt.WithKey(jwa.ES256K, ecKey))
		parsedToken, err := ParseJWT(string(signature), func(_ string) (crypto.PublicKey, error) {
			return ecKey.Public(), nil
		})
		require.NoError(t, err)

		assert.NotNil(t, parsedToken)
	})
}
