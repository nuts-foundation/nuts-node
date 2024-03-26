//go:build jwx_es256k

package oauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestES256k(t *testing.T) {
	t.Run("supported formats specifies ES256K", func(t *testing.T) {
		assert.Contains(t, DefaultOpenIDSupportedFormats()["jwt_vp_json"]["alg_values_supported"], "ES256K")
		assert.Contains(t, DefaultOpenIDSupportedFormats()["jwt_vc_json"]["alg_values_supported"], "ES256K")
	})
}
