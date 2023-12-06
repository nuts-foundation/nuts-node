package credential

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSupportedFormats_Match(t *testing.T) {
	t.Run("set 2 is subset", func(t *testing.T) {
		set1 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		}
		set2 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"JsonWebSignature2020"},
			},
		}
		expected := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"JsonWebSignature2020"},
			},
		}

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
	t.Run("set 2 does not match format params for JWT", func(t *testing.T) {
		set1 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		}
		set2 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256K"},
			},
		}
		expected := SupportedFormats{}

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
	t.Run("set 2 does not support one of the formats", func(t *testing.T) {
		set1 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		}
		set2 := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
		}
		expected := SupportedFormats{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
		}

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
}

func TestSupportedFormats_First(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		set := SupportedFormats{}
		format, params := set.First()
		assert.Equal(t, "", format)
		assert.Nil(t, params)
	})
	t.Run("non-empty", func(t *testing.T) {
		set := SupportedFormats{
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
		}
		format, params := set.First()
		assert.Equal(t, "jwt_vp", format)
		assert.Equal(t, map[string][]string{
			"alg_values_supported": {"ES256", "EdDSA"},
		}, params)
	})
}
