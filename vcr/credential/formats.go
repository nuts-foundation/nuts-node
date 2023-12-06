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

// DIFClaimFormats returns the given DIF claim formats as specified by https://identity.foundation/claim-format-registry/
// as Formats.
func DIFClaimFormats(formats map[string]map[string][]string) Formats {
	return Formats{
		Map:          formats,
		ParamAliases: map[string]string{
			// no aliases for this type
		},
	}
}

// OpenIDSupportedFormats returns the given OpenID supported formats as specified by the OpenID4VC family of specs.
func OpenIDSupportedFormats(formats map[string]map[string][]string) Formats {
	return Formats{
		Map: formats,
		ParamAliases: map[string]string{
			"alg_values_supported":        "alg",
			"proof_type_values_supported": "proof_type",
		},
	}
}

// Formats is a map of supported formats and their parameters according to https://identity.foundation/claim-format-registry/
// E.g., ldp_vp: {proof_type: [Ed25519Signature2018, JsonWebSignature2020]}
type Formats struct {
	Map          map[string]map[string][]string
	ParamAliases map[string]string
}

// Match takes the other supports formats and returns the formats that are supported by both sets.
// If a format is supported by both sets, it returns the intersection of the parameters.
// If a format is supported by both sets, but parameters overlap (e.g. supported cryptographic algorithms),
// the format is not included in the result.
func (f Formats) Match(other Formats) Formats {
	result := Formats{
		Map:          map[string]map[string][]string{},
		ParamAliases: map[string]string{},
	}

	for thisFormat, thisFormatParams := range f.Map {
		otherFormatParams := other.normalizeParameters(other.Map[thisFormat])
		if otherFormatParams == nil {
			// format not supported by other
			continue
		}

		result.Map[thisFormat] = map[string][]string{}
		for thisParam, thisValues := range f.normalizeParameters(thisFormatParams) {
			otherValues, supported := otherFormatParams[thisParam]
			if !supported {
				// param not supported by other
				continue
			}

			result.Map[thisFormat][thisParam] = []string{}
			for _, thisValue := range thisValues {
				for _, otherValue := range otherValues {
					if thisValue == otherValue {
						result.Map[thisFormat][thisParam] = append(result.Map[thisFormat][thisParam], thisValue)
					}
				}
			}
			if len(result.Map[thisFormat][thisParam]) == 0 {
				delete(result.Map[thisFormat], thisParam)
			}
		}
		if len(result.Map[thisFormat]) == 0 {
			delete(result.Map, thisFormat)
		}
	}

	return result
}

// First returns the first format and its parameters.
// If there are no formats, it returns an empty string and nil.
func (f Formats) First() (string, map[string][]string) {
	if len(f.Map) == 0 {
		return "", nil
	}
	// Sort the keys to get a deterministic result
	var formats []string
	for format := range f.Map {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return formats[0], f.normalizeParameters(f.Map[formats[0]])
}

// normalizeParameter normalizes the parameter name to the name used in the DIF spec.
func (f Formats) normalizeParameter(param string) string {
	if alias, ok := f.ParamAliases[param]; ok {
		return alias
	}
	return param
}

// normalizeParameters normalizes the parameter map to the names used in the DIF spec.
func (f Formats) normalizeParameters(params map[string][]string) map[string][]string {
	if params == nil {
		return nil
	}
	result := map[string][]string{}
	for param, values := range params {
		result[f.normalizeParameter(param)] = values
	}
	return result
}
