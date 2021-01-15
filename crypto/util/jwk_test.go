/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/stretchr/testify/assert"
)

func TestJwkToMap(t *testing.T) {
	t.Run("Generates map for RSA key", func(t *testing.T) {
		rsa := test.GenerateRSAKey()
		jwk, _ := jwk.New(rsa)

		jwkMap, err := JwkToMap(jwk)

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwkMap["kty"])
		}
	})
}

func TestMapToJwk(t *testing.T) {
	t.Run("Generates Jwk from map", func(t *testing.T) {
		jwkAsJSON := `{"d":"Ce3obeVsZeU3QaKBTQ-Qn-EaUfhEVViHbnP3gnLDrXNbiUf09s0Ti3RXd4601G8fAJ3zKlZmdEop59mK5BjAE8NOBmvP4uI7PYlJsDAE76mKghVxvN94qb-KwW4p0wix9RoC8TEtoE3EYCr428v-k4nTpMWXQcC_xkHVIfpoA6E","dp":"LGJtrCIxo2DlCSccu0ivH8YzUS9uUbsKyOgNEpV3IB3vqZToi_k8TkwN9XNXCMXkRYIGtRwkxvp9TWLtIEKMtQ","dq":"XhBVCRvFE_ccZ7rxzfu7LToeSNBPW07v68tM94pEV2MFfVBHdWJd-gHbIPGVwC55Th9vAh9dDmv0TvBVkiblkQ","e":"AQAB","kty":"RSA","n":"n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs","p":"1LoOk3MFiJpsjJCkMkaDb0TXXMxuZ5f9-iMVgR1ZoammzQziBj-72CrD21Rxmuuc6en8w4HtHLSOlPQtcOKzMw","q":"wAiSzr1NVdsYulhGYAa1ONZSKVxlFS7N_UAjPQgFf-xTYog2RbZfolheDv92mJp2qqFJdVMzQkbeMeTj9xqmGQ","qi":"eFqCOgR0wnpkjZGwh63pV8aNhh1-GfhYjqF2jSrh6rnsVHnhz3LRROSzUDarms7LjW3eHiygyHHSF2-ejTMMKQ"}`

		jwkMap := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &jwkMap)

		jwk, err := MapToJwk(jwkMap)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, jwa.KeyType("RSA"), jwk.KeyType())
		assert.NotNil(t, jwkMap["d"], "function altered input map")
	})

	t.Run("with missing data", func(t *testing.T) {
		jwkMap := map[string]interface{}{}
		_, err := MapToJwk(jwkMap)

		assert.Error(t, err)
	})
}

func TestMapsToJwkSet(t *testing.T) {
	t.Run("Generates set from maps", func(t *testing.T) {
		jwkAsJSON := `{"d":"Ce3obeVsZeU3QaKBTQ-Qn-EaUfhEVViHbnP3gnLDrXNbiUf09s0Ti3RXd4601G8fAJ3zKlZmdEop59mK5BjAE8NOBmvP4uI7PYlJsDAE76mKghVxvN94qb-KwW4p0wix9RoC8TEtoE3EYCr428v-k4nTpMWXQcC_xkHVIfpoA6E","dp":"LGJtrCIxo2DlCSccu0ivH8YzUS9uUbsKyOgNEpV3IB3vqZToi_k8TkwN9XNXCMXkRYIGtRwkxvp9TWLtIEKMtQ","dq":"XhBVCRvFE_ccZ7rxzfu7LToeSNBPW07v68tM94pEV2MFfVBHdWJd-gHbIPGVwC55Th9vAh9dDmv0TvBVkiblkQ","e":"AQAB","kty":"RSA","n":"n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs","p":"1LoOk3MFiJpsjJCkMkaDb0TXXMxuZ5f9-iMVgR1ZoammzQziBj-72CrD21Rxmuuc6en8w4HtHLSOlPQtcOKzMw","q":"wAiSzr1NVdsYulhGYAa1ONZSKVxlFS7N_UAjPQgFf-xTYog2RbZfolheDv92mJp2qqFJdVMzQkbeMeTj9xqmGQ","qi":"eFqCOgR0wnpkjZGwh63pV8aNhh1-GfhYjqF2jSrh6rnsVHnhz3LRROSzUDarms7LjW3eHiygyHHSF2-ejTMMKQ"}`

		jwkMap := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &jwkMap)

		set, err := MapsToJwkSet([]map[string]interface{}{jwkMap})

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, set.Keys, 1)
		assert.NotNil(t, jwkMap["d"], "function altered input map")
	})

	t.Run("with missing data", func(t *testing.T) {
		jwkMap := map[string]interface{}{}
		_, err := MapsToJwkSet([]map[string]interface{}{jwkMap})

		assert.Error(t, err)
	})
}

func TestPemToJwk(t *testing.T) {
	t.Run("generated jwk from pem", func(t *testing.T) {
		pub := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9wJQN59PYsvIsTrFuTqS\nLoUBgwdRfpJxOa5L8nOALxNk41MlAg7xnPbvnYrOHFucfWBTDOMTKBMSmD4WDkaF\ndVrXAML61z85Le8qsXfX6f7TbKMDm2u1O3cye+KdJe8zclK9sTFzSD0PP0wfw7wf\nlACe+PfwQgeOLPUWHaR6aDfaA64QEdfIzk/IL3S595ixaEn0huxMHgXFX35Vok+o\nQdbnclSTo6HUinkqsHUu/hGHApkE3UfT6GD6SaLiB9G4rAhlrDQ71ai872t4FfoK\n7skhe8sP2DstzAQRMf9FcetrNeTxNL7Zt4F/qKm80cchRZiFYPMCYyjQphyBCoJf\n0wIDAQAB\n-----END PUBLIC KEY-----"

		jwk, err := PemToJwk([]byte(pub))

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwk.KeyType())
		}
	})
	t.Run("invalid PEM", func(t *testing.T) {
		_, err := PemToJwk([]byte("hello world"))
		assert.Error(t, err)
	})
}

func Test_deepCopyMap(t *testing.T) {
	expected := map[string]interface{}{}
	expected["flat"] = "foobar"
	expected["nested"] = map[string]interface{}{
		"nested": map[string]interface{}{
			"nested": map[string]interface{}{
				"value": "ok",
			},
		},
	}

	actual := deepCopyMap(expected)
	assert.True(t, reflect.DeepEqual(actual, expected))
	// Assert it's actually a copy
	delete(expected, "flat")
	assert.False(t, reflect.DeepEqual(actual, expected))
}

func TestValidateJWK(t *testing.T) {
	jwkAsJSON := `{
  "e": "AQAB",
  "kty": "RSA",
  "n": "n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs",
  "x5c": ["MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="]
}`
	key := map[string]interface{}{}
	json.Unmarshal([]byte(jwkAsJSON), &key)
	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, ValidateJWK(key, key))
	})
	t.Run("error - invalid Go type", func(t *testing.T) {
		invalidMap := map[bool]interface{}{}
		assert.Error(t, ValidateJWK(key, invalidMap))
	})
	t.Run("error - invalid JWK", func(t *testing.T) {
		invalidMap := map[string]interface{}{
			"kty": "foobar",
		}
		assert.Error(t, ValidateJWK(key, invalidMap))
	})
}
