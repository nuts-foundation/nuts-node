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
	"testing"

	"github.com/nuts-foundation/nuts-node/v6/core/to"
	"github.com/stretchr/testify/assert"
)

func TestUnknownSelectionKeys(t *testing.T) {
	pdDeclaring := func(ids ...string) PresentationDefinition {
		var fields []Field
		for _, id := range ids {
			fields = append(fields, Field{Id: to.Ptr(id), Path: []string{"$.credentialSubject." + id}})
		}
		return PresentationDefinition{InputDescriptors: []*InputDescriptor{{Id: "descriptor", Constraints: &Constraints{Fields: fields}}}}
	}
	organizationPD := pdDeclaring("ura", "patient_id")
	serviceProviderPD := pdDeclaring("delegating_hcp")
	pdWithoutIDs := PresentationDefinition{InputDescriptors: []*InputDescriptor{
		{Id: "no_constraints"},
		{Id: "field_without_id", Constraints: &Constraints{Fields: []Field{{Path: []string{"$.type"}}}}},
	}}

	testCases := []struct {
		name      string
		selection map[string]string
		pds       []PresentationDefinition
		expected  []string
	}{
		{
			name:      "no selection",
			selection: nil,
			pds:       []PresentationDefinition{organizationPD},
		},
		{
			name:      "every key declared by the PD",
			selection: map[string]string{"ura": "1", "patient_id": "2"},
			pds:       []PresentationDefinition{organizationPD},
		},
		{
			name:      "key declared by a later descriptor",
			selection: map[string]string{"delegating_hcp": "did:test:hcp"},
			pds: []PresentationDefinition{{InputDescriptors: append(pdWithoutIDs.InputDescriptors,
				serviceProviderPD.InputDescriptors...)}},
		},
		{
			name:      "key declared by only one of several PDs is known",
			selection: map[string]string{"ura": "1", "delegating_hcp": "did:test:hcp"},
			pds:       []PresentationDefinition{organizationPD, serviceProviderPD},
		},
		{
			name:      "key declared by no PD is unknown",
			selection: map[string]string{"ura": "1", "typo": "x"},
			pds:       []PresentationDefinition{organizationPD, serviceProviderPD},
			expected:  []string{"typo"},
		},
		{
			name:      "every unknown key is returned, sorted",
			selection: map[string]string{"zeta": "1", "alpha": "2", "ura": "3", "mid": "4"},
			pds:       []PresentationDefinition{organizationPD},
			expected:  []string{"alpha", "mid", "zeta"},
		},
		{
			name:      "fields without id and descriptors without constraints declare nothing",
			selection: map[string]string{"ura": "1"},
			pds:       []PresentationDefinition{pdWithoutIDs},
			expected:  []string{"ura"},
		},
		{
			// The value plays no role: an empty value is still a selection for a declared key.
			name:      "key with an empty value is checked by its name only",
			selection: map[string]string{"ura": ""},
			pds:       []PresentationDefinition{organizationPD},
		},
		{
			name:      "empty key is unknown: fields without id do not declare it",
			selection: map[string]string{"": "x"},
			pds:       []PresentationDefinition{pdWithoutIDs},
			expected:  []string{""},
		},
		{
			// Checking keys does not depend on whether the PD is otherwise valid.
			name:      "keys of a PD with duplicate input descriptor ids are declared",
			selection: map[string]string{"ura": "1"},
			pds: []PresentationDefinition{{InputDescriptors: []*InputDescriptor{
				{Id: "duplicate", Constraints: &Constraints{Fields: []Field{{Id: to.Ptr("ura"), Path: []string{"$.credentialSubject.ura"}}}}},
				{Id: "duplicate", Constraints: &Constraints{Fields: []Field{{Path: []string{"$.type"}}}}},
			}}},
		},
		{
			name:      "no PDs: every key is unknown",
			selection: map[string]string{"ura": "1"},
			expected:  []string{"ura"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, UnknownSelectionKeys(tc.selection, tc.pds...))
		})
	}
}

func TestScalarAsText(t *testing.T) {
	testCases := []struct {
		name       string
		value      any
		expected   string
		comparable bool
	}{
		{name: "string is used as is", value: "URA-001", expected: "URA-001", comparable: true},
		{name: "empty string is comparable", value: "", expected: "", comparable: true},
		{name: "whole number has no decimals", value: float64(3), expected: "3", comparable: true},
		{name: "fraction keeps its decimals", value: 1.5, expected: "1.5", comparable: true},
		{name: "large number has no exponent", value: float64(123456789012), expected: "123456789012", comparable: true},
		{name: "negative number", value: float64(-2), expected: "-2", comparable: true},
		{name: "true", value: true, expected: "true", comparable: true},
		{name: "false", value: false, expected: "false", comparable: true},
		{name: "array is not comparable", value: []any{"a"}},
		{name: "object is not comparable", value: map[string]any{"a": "b"}},
		{name: "nil is not comparable", value: nil},
		{name: "non-JSON number type is not comparable", value: 3},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := ScalarAsText(tc.value)

			assert.Equal(t, tc.comparable, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
