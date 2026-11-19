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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFieldIDs(t *testing.T) {
	// descriptor builds an input descriptor JSON object with the given fields (JSON objects)
	descriptor := func(id string, fields ...string) string {
		result := `{"id": "` + id + `", "constraints": {"fields": [`
		for i, field := range fields {
			if i > 0 {
				result += ","
			}
			result += field
		}
		return result + `]}}`
	}
	definition := func(id string, descriptors ...string) PresentationDefinition {
		raw := `{"id": "` + id + `", "input_descriptors": [`
		for i, d := range descriptors {
			if i > 0 {
				raw += ","
			}
			raw += d
		}
		raw += `]}`
		var result PresentationDefinition
		require.NoError(t, json.Unmarshal([]byte(raw), &result))
		return result
	}

	testCases := []struct {
		name        string
		definitions []PresentationDefinition
		// expectedErrors lists the expected error messages, in the order they're reported. Empty means valid.
		expectedErrors []string
	}{
		{
			name:        "no definitions",
			definitions: nil,
		},
		{
			name: "fields without id",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"path": ["$.a"]}`, `{"path": ["$.b"]}`),
				descriptor("d2", `{"path": ["$.a"]}`),
			)},
		},
		{
			name: "ids used in one input descriptor only",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string"}}`),
				descriptor("d2", `{"id": "b", "path": ["$.b"], "filter": {"type": "number"}}`),
			)},
		},
		{
			name: "optional field with an id used in one input descriptor only",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "optional": true}`),
				descriptor("d2", `{"id": "b", "path": ["$.b"]}`),
			)},
		},
		{
			name: "same id with different paths",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "ura", "path": ["$.credentialSubject.ura"], "filter": {"type": "string"}}`),
				descriptor("d2", `{"id": "ura", "path": ["$.credentialSubject.organization.ura"], "filter": {"type": "string"}}`),
			)},
		},
		{
			name: "same id with pattern-only filters",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"pattern": "^x"}}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"], "filter": {"pattern": "^y"}}`),
			)},
		},
		{
			name: "same id with type and const on one side only",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "x"}}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"]}`),
			)},
		},
		{
			name: "same id with different enums",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "enum": ["x", "y"]}}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "enum": ["z"]}}`),
			)},
		},
		{
			name: "same id with same type and const",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "x"}}`),
				descriptor("d2", `{"id": "a", "path": ["$.b"], "filter": {"type": "string", "const": "x"}}`),
			)},
		},
		{
			name: "same id in two presentation definitions with same type",
			definitions: []PresentationDefinition{
				definition("pd1", descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string"}}`)),
				definition("pd2", descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string"}}`)),
			},
		},
		{
			name: "id used twice within one input descriptor",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"]}`, `{"id": "a", "path": ["$.b"]}`),
			)},
			expectedErrors: []string{
				"field id 'a' is used on 2 fields of input descriptor 'd1' (presentation definition 'pd'), it must be unique within an input descriptor",
			},
		},
		{
			name: "same id with conflicting types",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string"}}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"], "filter": {"type": "number"}}`),
			)},
			expectedErrors: []string{
				"field id 'a' is used in input descriptor 'd1' (presentation definition 'pd'), input descriptor 'd2' (presentation definition 'pd'), " +
					"with conflicting filter types: 'string' in input descriptor 'd1' (presentation definition 'pd'), 'number' in input descriptor 'd2' (presentation definition 'pd')",
			},
		},
		{
			name: "same id with conflicting consts",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "x"}}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "y"}}`),
			)},
			expectedErrors: []string{
				"field id 'a' is used in input descriptor 'd1' (presentation definition 'pd'), input descriptor 'd2' (presentation definition 'pd'), " +
					"with conflicting filter consts: 'x' in input descriptor 'd1' (presentation definition 'pd'), 'y' in input descriptor 'd2' (presentation definition 'pd')",
			},
		},
		{
			name: "same id in two presentation definitions with conflicting consts",
			definitions: []PresentationDefinition{
				definition("pd_org", descriptor("d", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "x"}}`)),
				definition("pd_sp", descriptor("d", `{"id": "a", "path": ["$.a"], "filter": {"type": "string", "const": "y"}}`)),
			},
			expectedErrors: []string{
				"field id 'a' is used in input descriptor 'd' (presentation definition 'pd_org'), input descriptor 'd' (presentation definition 'pd_sp'), " +
					"with conflicting filter consts: 'x' in input descriptor 'd' (presentation definition 'pd_org'), 'y' in input descriptor 'd' (presentation definition 'pd_sp')",
			},
		},
		{
			name: "shared id on an optional field",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"]}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"], "optional": true}`),
			)},
			expectedErrors: []string{
				"field id 'a' is used in input descriptor 'd1' (presentation definition 'pd'), input descriptor 'd2' (presentation definition 'pd'), " +
					"but is optional in input descriptor 'd2' (presentation definition 'pd'): a field id used in more than one input descriptor may not be optional",
			},
		},
		{
			name: "shared id on a field with optional false",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1", `{"id": "a", "path": ["$.a"], "optional": false}`),
				descriptor("d2", `{"id": "a", "path": ["$.a"]}`),
			)},
		},
		{
			name: "all violations are reported, ordered by field id",
			definitions: []PresentationDefinition{definition("pd",
				descriptor("d1",
					`{"id": "b", "path": ["$.b"], "filter": {"type": "string"}}`,
					`{"id": "a", "path": ["$.a"]}`,
					`{"id": "a", "path": ["$.a2"]}`,
				),
				descriptor("d2", `{"id": "b", "path": ["$.b"], "filter": {"type": "number"}, "optional": true}`),
			)},
			expectedErrors: []string{
				"field id 'a' is used on 2 fields of input descriptor 'd1' (presentation definition 'pd'), it must be unique within an input descriptor",
				"field id 'b' is used in input descriptor 'd1' (presentation definition 'pd'), input descriptor 'd2' (presentation definition 'pd'), " +
					"but is optional in input descriptor 'd2' (presentation definition 'pd'): a field id used in more than one input descriptor may not be optional",
				"field id 'b' is used in input descriptor 'd1' (presentation definition 'pd'), input descriptor 'd2' (presentation definition 'pd'), " +
					"with conflicting filter types: 'string' in input descriptor 'd1' (presentation definition 'pd'), 'number' in input descriptor 'd2' (presentation definition 'pd')",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFieldIDs(tc.definitions...)

			if len(tc.expectedErrors) == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			joined, ok := err.(interface{ Unwrap() []error })
			require.True(t, ok, "expected joined errors")
			var actual []string
			for _, e := range joined.Unwrap() {
				actual = append(actual, e.Error())
			}
			assert.Equal(t, tc.expectedErrors, actual)
		})
	}
}
