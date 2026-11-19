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
	"errors"
	"testing"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/v6/core/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPresentationDefinition_ResolveConstraintsFields_FieldValueAgreement(t *testing.T) {
	// credentialWith returns a credential whose subject has the given value at $.credentialSubject.value.
	// A nil value leaves the property out, so an optional field on that path does not resolve.
	credentialWith := func(value interface{}) vc.VerifiableCredential {
		subject := map[string]interface{}{"id": "did:example:subject"}
		if value != nil {
			subject["value"] = value
		}
		return vc.VerifiableCredential{CredentialSubject: []map[string]interface{}{subject}}
	}
	// descriptor returns an input descriptor with one field, id "shared", on $.credentialSubject.value.
	descriptor := func(id string, optional bool) *InputDescriptor {
		return &InputDescriptor{Id: id, Constraints: &Constraints{Fields: []Field{{
			Id:       to.Ptr("shared"),
			Path:     []string{"$.credentialSubject.value"},
			Optional: to.Ptr(optional),
		}}}}
	}
	twoDescriptors := PresentationDefinition{InputDescriptors: []*InputDescriptor{descriptor("first", true), descriptor("second", true)}}

	type testCase struct {
		name       string
		definition PresentationDefinition
		first      interface{}
		second     interface{}
		// expected is the value of "shared" in the result, when no error is expected
		expected interface{}
		// expectedError is the error message, empty when no error is expected
		expectedError string
	}
	testCases := []testCase{
		{name: "same strings agree", definition: twoDescriptors, first: "a", second: "a", expected: "a"},
		{name: "different strings conflict", definition: twoDescriptors, first: "a", second: "b",
			expectedError: "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'first' and 'second'"},
		{name: "unresolved first value is ignored", definition: twoDescriptors, first: nil, second: "b", expected: "b"},
		{name: "unresolved second value is ignored and does not overwrite", definition: twoDescriptors, first: "a", second: nil, expected: "a"},
		{name: "unresolved in both keeps the id with a nil value", definition: twoDescriptors, first: nil, second: nil, expected: nil},
		{name: "string and number with the same text agree, first descriptor's value is kept", definition: twoDescriptors, first: "1", second: float64(1), expected: "1"},
		{name: "number and string with the same text agree, first descriptor's value is kept", definition: twoDescriptors, first: float64(1), second: "1", expected: float64(1)},
		{name: "boolean and string with the same text agree", definition: twoDescriptors, first: true, second: "true", expected: true},
		{name: "numbers with different text conflict", definition: twoDescriptors, first: float64(1), second: 1.5,
			expectedError: "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'first' and 'second'"},
		{name: "equal arrays agree", definition: twoDescriptors, first: []interface{}{"a", "b"}, second: []interface{}{"a", "b"}, expected: []interface{}{"a", "b"}},
		{name: "different arrays conflict", definition: twoDescriptors, first: []interface{}{"a", "b"}, second: []interface{}{"b", "a"},
			expectedError: "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'first' and 'second'"},
		{name: "equal objects agree regardless of key order", definition: twoDescriptors,
			first: map[string]interface{}{"x": "1", "y": "2"}, second: map[string]interface{}{"y": "2", "x": "1"}, expected: map[string]interface{}{"x": "1", "y": "2"}},
		{name: "different objects conflict", definition: twoDescriptors, first: map[string]interface{}{"x": "1"}, second: map[string]interface{}{"x": "2"},
			expectedError: "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'first' and 'second'"},
		{name: "scalar never equals a non-scalar", definition: twoDescriptors, first: "a", second: []interface{}{"a"},
			expectedError: "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'first' and 'second'"},
		{name: "id declared in one input descriptor only", definition: PresentationDefinition{InputDescriptors: []*InputDescriptor{
			descriptor("first", true),
			{Id: "second", Constraints: &Constraints{Fields: []Field{{Path: []string{"$.credentialSubject.value"}}}}},
		}}, first: "a", second: "b", expected: "a"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credentialMap := map[string]vc.VerifiableCredential{
				"first":  credentialWith(tc.first),
				"second": credentialWith(tc.second),
			}

			fieldValues, err := tc.definition.ResolveConstraintsFields(credentialMap)

			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
				assert.True(t, errors.Is(err, ErrConflictingFieldValues))
				assert.Nil(t, fieldValues)
				return
			}
			require.NoError(t, err)
			require.Contains(t, fieldValues, "shared")
			assert.Equal(t, tc.expected, fieldValues["shared"])
		})
	}
	t.Run("descriptors are visited in definition order, whatever the order of the credential map", func(t *testing.T) {
		// With many input descriptors whose values agree as text but differ in type, the value of the first input
		// descriptor in the definition must be returned every time; Go randomizes map iteration order, so repeating
		// the call would expose a dependency on the order of the credential map.
		definition := PresentationDefinition{}
		credentialMap := map[string]vc.VerifiableCredential{}
		for i, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			definition.InputDescriptors = append(definition.InputDescriptors, descriptor(id, false))
			if i == 0 {
				credentialMap[id] = credentialWith("1")
			} else {
				credentialMap[id] = credentialWith(float64(1))
			}
		}
		for i := 0; i < 50; i++ {
			fieldValues, err := definition.ResolveConstraintsFields(credentialMap)
			require.NoError(t, err)
			require.Equal(t, "1", fieldValues["shared"])
		}
	})
	t.Run("conflict names the descriptor that resolved the value first, in definition order", func(t *testing.T) {
		definition := PresentationDefinition{InputDescriptors: []*InputDescriptor{
			descriptor("z_unresolved", true), descriptor("y_resolves", true), descriptor("x_differs", true),
		}}
		credentialMap := map[string]vc.VerifiableCredential{
			"z_unresolved": credentialWith(nil),
			"y_resolves":   credentialWith("a"),
			"x_differs":    credentialWith("b"),
		}
		for i := 0; i < 50; i++ {
			_, err := definition.ResolveConstraintsFields(credentialMap)
			require.EqualError(t, err, "fields sharing an id resolve to different values: field id 'shared' in input descriptors 'y_resolves' and 'x_differs'")
		}
	})
}
