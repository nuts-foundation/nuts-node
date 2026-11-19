/*
 * Copyright (C) 2026 Nuts community
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

package pe

import (
	"slices"
	"strconv"
)

// UnknownSelectionKeys returns the keys of selection that no field id in any of the given presentation definitions
// declares, sorted. A field id names one value across a whole token request, so a key only needs to be declared by
// one of the PDs of the request; it is unknown when none of them declares it. Such a key cannot select anything,
// which signals a mistake by the caller (e.g. a typo), so callers should reject it rather than ignore it.
// Returns nil when every key is declared.
func UnknownSelectionKeys(selection map[string]string, presentationDefinitions ...PresentationDefinition) []string {
	declared := make(map[string]bool)
	for _, pd := range presentationDefinitions {
		for _, descriptor := range pd.InputDescriptors {
			if descriptor == nil || descriptor.Constraints == nil {
				continue
			}
			for _, field := range descriptor.Constraints.Fields {
				if field.Id != nil {
					declared[*field.Id] = true
				}
			}
		}
	}
	var unknown []string
	for key := range selection {
		if !declared[key] {
			unknown = append(unknown, key)
		}
	}
	slices.Sort(unknown)
	return unknown
}

// ScalarAsText returns the text form of a field value resolved from a credential, so it can be compared with a
// value that was given as text (such as a credential_selection entry), or with another resolved value.
//
// The comparison rule: two values are equal when their text forms are equal. Only scalars have a text form:
//   - a string is used as is;
//   - a number (float64, as produced by JSON decoding) is formatted in its shortest decimal form without exponent,
//     so 3 becomes "3" and 1.5 becomes "1.5";
//   - a boolean becomes "true" or "false".
//
// Any other value (an array, an object, nil) is not comparable: ScalarAsText returns false, and such a value never
// equals a value given as text.
func ScalarAsText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}
