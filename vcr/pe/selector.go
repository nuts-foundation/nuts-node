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
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
)

type fieldSelection struct {
	fieldID  string
	expected string
}

// NewSelectionSelector creates a CredentialSelector that filters candidates using
// named field ID values from the credential_selection parameter.
func NewSelectionSelector(selection map[string]string, pd PresentationDefinition, fallback CredentialSelector) (CredentialSelector, error) {
	descriptorSelections := make(map[string][]fieldSelection)

	for _, desc := range pd.InputDescriptors {
		if desc.Constraints == nil {
			continue
		}
		for _, field := range desc.Constraints.Fields {
			if field.Id == nil {
				continue
			}
			if expected, ok := selection[*field.Id]; ok {
				descriptorSelections[desc.Id] = append(descriptorSelections[desc.Id], fieldSelection{
					fieldID:  *field.Id,
					expected: expected,
				})
			}
		}
	}

	// Validate all selection keys match at least one field ID in the PD.
	for key := range selection {
		found := false
		for _, sels := range descriptorSelections {
			for _, sel := range sels {
				if sel.fieldID == key {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("credential_selection key '%s' does not match any field id in the presentation definition", key)
		}
	}

	return func(descriptor InputDescriptor, candidates []vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
		selections, ok := descriptorSelections[descriptor.Id]
		if !ok {
			return fallback(descriptor, candidates)
		}

		var matched []vc.VerifiableCredential
		for _, candidate := range candidates {
			if descriptor.Constraints == nil {
				continue
			}
			isMatch, values, err := matchConstraint(descriptor.Constraints, candidate)
			if err != nil || !isMatch {
				continue
			}
			if matchesSelections(values, selections) {
				matched = append(matched, candidate)
			}
		}

		if len(matched) == 0 {
			return nil, fmt.Errorf("input descriptor '%s': %w", descriptor.Id, ErrNoCredentials)
		}
		if len(matched) > 1 {
			return nil, fmt.Errorf("input descriptor '%s': %w", descriptor.Id, ErrMultipleCredentials)
		}
		return &matched[0], nil
	}, nil
}

func matchesSelections(values map[string]interface{}, selections []fieldSelection) bool {
	for _, sel := range selections {
		resolved, ok := values[sel.fieldID]
		if !ok {
			return false
		}
		if str, ok := resolved.(string); ok {
			if str != sel.expected {
				return false
			}
		} else if fmt.Sprintf("%v", resolved) != sel.expected {
			return false
		}
	}
	return true
}
