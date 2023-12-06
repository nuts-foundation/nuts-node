/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package credential

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFormats_Match(t *testing.T) {
	t.Run("DIF - set 2 is subset", func(t *testing.T) {
		set1 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})
		set2 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"JsonWebSignature2020"},
			},
		})
		expected := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"JsonWebSignature2020"},
			},
		})

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
	t.Run("one set PEX style, other set OpenID4VC style", func(t *testing.T) {
		set1 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})
		set2 := OpenIDSupportedFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})
		expected := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})

		t.Run("PEX match OpenID", func(t *testing.T) {
			result := set1.Match(set2)
			assert.Equal(t, expected, result)
		})
		t.Run("OpenID match PEX", func(t *testing.T) {
			result := set2.Match(set1)
			assert.Equal(t, expected, result)
		})
	})
	t.Run("set 2 does not match format params for JWT", func(t *testing.T) {
		set1 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})
		set2 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg": {"ES256K"},
			},
		})
		expected := DIFClaimFormats(map[string]map[string][]string{})

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
	t.Run("set 2 does not support one of the formats", func(t *testing.T) {
		set1 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
		})
		set2 := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
		})
		expected := DIFClaimFormats(map[string]map[string][]string{
			"jwt_vp": {
				"alg_values_supported": {"ES256"},
			},
		})

		result := set1.Match(set2)
		assert.Equal(t, expected, result)
	})
}

func TestSupportedFormats_First(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		set := Formats{}
		format, params := set.First()
		assert.Equal(t, "", format)
		assert.Nil(t, params)
	})
	t.Run("non-empty", func(t *testing.T) {
		set := OpenIDSupportedFormats(map[string]map[string][]string{
			"ldp_vp": {
				"proof_type_values_supported": {"Ed25519Signature2018", "JsonWebSignature2020"},
			},
			"jwt_vp": {
				"alg_values_supported": {"ES256", "EdDSA"},
			},
		})
		format, params := set.First()
		assert.Equal(t, "jwt_vp", format)
		assert.Equal(t, map[string][]string{
			"alg": {"ES256", "EdDSA"},
		}, params)
	})
}
