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

// DIFClaimFormats returns the given DIF claim formats as specified by https://identity.foundation/claim-format-registry/
// as Formats.
func DIFClaimFormats(formats map[string]map[string][]string) Formats {
	return Formats{
		Map:          formats,
		ParamAliases: map[string]string{
			// no aliases for this type
		},
		FormatAliases: map[string]string{
			"jwt_vp_json": "jwt_vp",
			"jwt_vc_json": "jwt_vc",
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
	Map           map[string]map[string][]string
	ParamAliases  map[string]string
	// FormatAliases allows aliasing the VP and VC formats. This feature can be removed when https://identity.foundation/claim-format-registry/ and the OpenID4VC specifications have agreed on the format designators.
	FormatAliases map[string]string
}

// Match takes the other supports formats and returns the formats that are supported by both sets.
// If a format is supported by both sets, it returns the intersection of the parameters.
// If a format is supported by both sets, but parameters overlap (e.g. supported cryptographic algorithms),
// the format is not included in the result.
func (f Formats) Match(other Formats) Formats {
	aliases := f.FormatAliases
	if aliases == nil {
		aliases = other.FormatAliases
	}
	result := Formats{
		Map:           map[string]map[string][]string{},
		ParamAliases:  map[string]string{},
		FormatAliases: aliases,
	}

	for thisFormat, thisFormatParams := range f.Map {
		otherFormat := other.normalizeFormat(thisFormat)
		otherFormatParams := other.normalizeParameters(other.Map[otherFormat])
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

// normalizeParameter normalizes the parameter name to the name used in the DIF spec.
func (f Formats) normalizeParameter(param string) string {
	if alias, ok := f.ParamAliases[param]; ok {
		return alias
	}
	return param
}

func (f Formats) normalizeFormat(format string) string {
	if alias, ok := f.FormatAliases[format]; ok {
		return alias
	}
	return format
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
