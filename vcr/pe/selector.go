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

// NewFieldSelector creates a CredentialSelector that filters candidates by
// matching PD field ID values from the credential_selection parameter.
// Only constant (equality) matching is supported; pattern-based filters are
// already evaluated by matchConstraint before the selector runs.
func NewFieldSelector(selection map[string]string, pd PresentationDefinition, fallback CredentialSelector) (CredentialSelector, error) {
	descriptorSelections := make(map[string][]fieldSelection)
	matchedKeys := make(map[string]bool)

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
				matchedKeys[*field.Id] = true
			}
		}
	}

	// Validate all selection keys match at least one field ID in the PD.
	for key := range selection {
		if !matchedKeys[key] {
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
			if err != nil {
				return nil, fmt.Errorf("input descriptor '%s': %w", descriptor.Id, err)
			}
			if !isMatch {
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
		str, ok := resolved.(string)
		if !ok || str != sel.expected {
			return false
		}
	}
	return true
}
