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

import "sort"

// algValuesSupported contains a list of supported cipher suites for jwt_vc_json & jwt_vp_json presentation formats
// Recommended list of options https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// TODO: validate list, should reflect current recommendations from https://www.ncsc.nl
var algValuesSupported = []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// proofTypeValuesSupported contains a list of supported cipher suites for ldp_vc & ldp_vp presentation formats
// Recommended list of options https://w3c-ccg.github.io/ld-cryptosuite-registry/
var proofTypeValuesSupported = []string{"JsonWebSignature2020"}

// DefaultSupportedFormats returns the supported formats and is used in the
//   - Authorization Server's metadata field `vp_formats_supported`
//   - Client's metadata field `vp_formats`
//
// TODO: spec is very unclear about this part.
// See https://github.com/nuts-foundation/nuts-node/issues/2447
func DefaultSupportedFormats() SupportedFormats {
	return SupportedFormats{
		"jwt_vp_json": {"alg_values_supported": algValuesSupported},
		"jwt_vc_json": {"alg_values_supported": algValuesSupported},
		"ldp_vc":      {"proof_type_values_supported": proofTypeValuesSupported},
		"ldp_vp":      {"proof_type_values_supported": proofTypeValuesSupported},
	}
}

// SupportedFormats is a map of supported formats and their parameters.
// E.g., ldp_vp: {proof_type_values_supported: [Ed25519Signature2018, JsonWebSignature2020]}
type SupportedFormats map[string]map[string][]string

// Match takes the other supports formats and returns the formats that are supported by both sets.
// If a format is supported by both sets, it returns the intersection of the parameters.
// If a format is supported by both sets, but parameters overlap (e.g. supported cryptographic algorithms),
// the format is not included in the result.
func (f SupportedFormats) Match(other SupportedFormats) SupportedFormats {
	result := SupportedFormats{}

	for thisFormat, thisFormatParams := range f {
		otherFormatParams, supported := other[thisFormat]
		if !supported {
			// format not supported by other
			continue
		}

		result[thisFormat] = map[string][]string{}
		for thisParam, thisValues := range thisFormatParams {
			otherValues, supported := otherFormatParams[thisParam]
			if !supported {
				// param not supported by other
				continue
			}

			result[thisFormat][thisParam] = []string{}
			for _, thisValue := range thisValues {
				for _, otherValue := range otherValues {
					if thisValue == otherValue {
						result[thisFormat][thisParam] = append(result[thisFormat][thisParam], thisValue)
					}
				}
			}
			if len(result[thisFormat][thisParam]) == 0 {
				delete(result[thisFormat], thisParam)
			}
		}
		if len(result[thisFormat]) == 0 {
			delete(result, thisFormat)
		}
	}

	return result
}

// First returns the first format and its parameters.
// If there are no formats, it returns an empty string and nil.
func (f SupportedFormats) First() (string, map[string][]string) {
	if len(f) == 0 {
		return "", nil
	}
	// Sort the keys to get a deterministic result
	var formats []string
	for format := range f {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return formats[0], f[formats[0]]
}
