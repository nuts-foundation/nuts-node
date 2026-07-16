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
	"sort"
	"strings"
)

// UnknownSelectionKeysError is returned by ValidateSelectionKeys when the caller supplied
// credential_selection keys that are not field ids in any of the supplied presentation
// definitions.
type UnknownSelectionKeysError struct {
	// Keys holds every unknown key, sorted.
	Keys []string
}

func (e *UnknownSelectionKeysError) Error() string {
	return "unknown credential_selection keys: " + strings.Join(e.Keys, ", ")
}

// ValidateSelectionKeys checks that every credential_selection key is a field id in at least one
// of the supplied presentation definitions (the union: one PD for a single-VP request, two for a
// two-VP request). Key names only are validated; values, including empty strings, play no role.
// It returns an UnknownSelectionKeysError naming every unknown key, or nil.
func ValidateSelectionKeys(selection map[string]string, pds ...PresentationDefinition) error {
	known := make(map[string]bool)
	for _, pd := range pds {
		for _, descriptor := range pd.InputDescriptors {
			if descriptor.Constraints == nil {
				continue
			}
			for _, field := range descriptor.Constraints.Fields {
				if field.Id != nil {
					known[*field.Id] = true
				}
			}
		}
	}
	var unknown []string
	for key := range selection {
		if !known[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return &UnknownSelectionKeysError{Keys: unknown}
}
