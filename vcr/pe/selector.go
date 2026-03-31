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
	"strconv"

	"github.com/nuts-foundation/go-did/vc"
)

// CredentialSelector picks one credential from a list of candidates that all match a given input descriptor.
// It is called by matchConstraints after collecting all matching VCs for an input descriptor.
//
// Return values:
//   - (*vc, nil): a credential was selected successfully.
//   - (nil, nil): no credential was selected. The input descriptor is not fulfilled, which may
//     be acceptable depending on submission requirements (e.g., pick rules with min: 0).
//   - (nil, ErrNoCredentials): no candidates matched the selector's criteria. Treated as a soft
//     failure: the input descriptor is not fulfilled, but submission requirements may still accept
//     this (e.g., pick rules with min: 0).
//   - (nil, ErrMultipleCredentials): multiple candidates matched but the selector requires exactly one.
//     This is a hard failure — the match is aborted.
//   - (nil, other error): any other error is a hard failure.
//
// Selectors that are lenient (like FirstMatchSelector) may return (nil, nil) to let the caller decide.
type CredentialSelector func(descriptor InputDescriptor, candidates []vc.VerifiableCredential) (*vc.VerifiableCredential, error)

// FirstMatchSelector is the default CredentialSelector that picks the first matching credential.
// This preserves the existing behavior of matchConstraints.
func FirstMatchSelector(_ InputDescriptor, candidates []vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	return &candidates[0], nil
}

type fieldSelection struct {
	fieldID  string
	expected string
}

// NewFieldSelector creates a CredentialSelector that filters candidates by
// matching PD field ID values from the credential_selection parameter.
// Only constant (equality) matching is supported; pattern-based filters are
// already evaluated by matchConstraint before the selector runs.
// Returns (nil, nil) for input descriptors without matching selection keys,
// signalling the builder to apply its default selector.
func NewFieldSelector(selection map[string]string, pd PresentationDefinition) (CredentialSelector, error) {
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
			return nil, nil
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
		var str string
		switch v := resolved.(type) {
		case string:
			str = v
		case float64:
			str = strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			str = strconv.FormatBool(v)
		default:
			return false
		}
		if str != sel.expected {
			return false
		}
	}
	return true
}
