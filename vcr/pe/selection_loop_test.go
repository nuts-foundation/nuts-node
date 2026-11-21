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
	"strings"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/v6/core/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selectionCredential returns a JSON-LD credential with the given id and credential subject.
func selectionCredential(id string, subject map[string]any) vc.VerifiableCredential {
	credentialID := ssi.MustParseURI(id)
	return credentialToJSONLD(vc.VerifiableCredential{ID: &credentialID, CredentialSubject: []map[string]any{subject}})
}

// selectionDescriptor returns an input descriptor that matches credentials whose credentialSubject.kind equals kind,
// with the given extra fields.
func selectionDescriptor(id string, kind string, fields ...Field) *InputDescriptor {
	kindField := Field{Path: []string{"$.credentialSubject.kind"}, Filter: &Filter{Type: "string", Const: to.Ptr(kind)}}
	return &InputDescriptor{Id: id, Constraints: &Constraints{Fields: append([]Field{kindField}, fields...)}}
}

// idField returns a field with the given id on credentialSubject.<property>.
func idField(id string, property string) Field {
	return Field{Id: to.Ptr(id), Path: []string{"$.credentialSubject." + property}}
}

// optionalIDField returns an optional field with the given id on credentialSubject.<property>.
func optionalIDField(id string, property string) Field {
	field := idField(id, property)
	field.Optional = to.Ptr(true)
	return field
}

// selectedCredentialIDs returns, per input descriptor id, the id of the selected credential ("" for none).
func selectedCredentialIDs(candidates []Candidate) map[string]string {
	result := make(map[string]string)
	for _, candidate := range candidates {
		result[candidate.InputDescriptor.Id] = ""
		if candidate.VC != nil {
			result[candidate.InputDescriptor.Id] = candidate.VC.ID.String()
		}
	}
	return result
}

// permutations returns every order of the given input descriptors.
func permutations(descriptors []*InputDescriptor) [][]*InputDescriptor {
	if len(descriptors) <= 1 {
		return [][]*InputDescriptor{descriptors}
	}
	var result [][]*InputDescriptor
	for i := range descriptors {
		rest := make([]*InputDescriptor, 0, len(descriptors)-1)
		rest = append(rest, descriptors[:i]...)
		rest = append(rest, descriptors[i+1:]...)
		for _, permutation := range permutations(rest) {
			result = append(result, append([]*InputDescriptor{descriptors[i]}, permutation...))
		}
	}
	return result
}

func TestPresentationDefinition_selectCredentials(t *testing.T) {
	// Providers and delegations: a delegation belongs to the provider with the same ura.
	p1 := selectionCredential("P1", map[string]any{"kind": "provider", "ura": "1", "name": "Org A"})
	p2 := selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2", "name": "Org B"})
	d1 := selectionCredential("D1", map[string]any{"kind": "delegation", "ura": "1", "employee": "e1"})
	d1b := selectionCredential("D1b", map[string]any{"kind": "delegation", "ura": "1", "employee": "e2"})
	d2 := selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"})
	d2copy := selectionCredential("D2copy", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"})
	d2b := selectionCredential("D2b", map[string]any{"kind": "delegation", "ura": "2", "employee": "e2"})
	d3 := selectionCredential("D3", map[string]any{"kind": "delegation", "ura": "3", "employee": "e1"})
	provider := selectionDescriptor("provider", "provider", idField("ura", "ura"), idField("org_name", "name"))
	delegation := selectionDescriptor("delegation", "delegation", idField("ura", "ura"), idField("employee", "employee"))

	type testCase struct {
		name        string
		descriptors []*InputDescriptor
		vcs         []vc.VerifiableCredential
		selection   map[string]string
		// expected maps input descriptor id to the selected credential id ("" for none).
		expected map[string]string
		// expectedReasons maps input descriptor id to text the explanation of a missing credential must contain.
		expectedReasons map[string][]string
		// orderIndependent cases must give the same result for every order of the input descriptors.
		orderIndependent bool
	}
	testCases := []testCase{
		{
			name: "without field ids every descriptor gets its first match",
			descriptors: []*InputDescriptor{
				selectionDescriptor("provider", "provider"),
				selectionDescriptor("delegation", "delegation"),
			},
			vcs:              []vc.VerifiableCredential{p1, p2, d2, d1},
			expected:         map[string]string{"provider": "P1", "delegation": "D2"},
			orderIndependent: true,
		},
		{
			name: "ids that are not shared, without selection: first match per descriptor",
			descriptors: []*InputDescriptor{
				selectionDescriptor("provider", "provider", idField("ura", "ura")),
				selectionDescriptor("delegation", "delegation", idField("employee", "employee")),
			},
			vcs:      []vc.VerifiableCredential{p2, p1, d2b, d1},
			expected: map[string]string{"provider": "P2", "delegation": "D2b"},
		},
		{
			name:             "unpinned delegation follows the provider selected by a key only the provider declares",
			descriptors:      []*InputDescriptor{provider, delegation},
			vcs:              []vc.VerifiableCredential{p1, p2, d1, d2},
			selection:        map[string]string{"org_name": "Org B"},
			expected:         map[string]string{"provider": "P2", "delegation": "D2"},
			orderIndependent: true,
		},
		{
			name:             "unpinned delegation follows the only provider credential in the wallet",
			descriptors:      []*InputDescriptor{provider, delegation},
			vcs:              []vc.VerifiableCredential{p2, d1, d2},
			expected:         map[string]string{"provider": "P2", "delegation": "D2"},
			orderIndependent: true,
		},
		{
			name:             "reverse direction: provider follows the delegation selected by a key only the delegation declares",
			descriptors:      []*InputDescriptor{provider, delegation},
			vcs:              []vc.VerifiableCredential{p1, p2, d1, d2b},
			selection:        map[string]string{"employee": "e2"},
			expected:         map[string]string{"provider": "P2", "delegation": "D2b"},
			orderIndependent: true,
		},
		{
			name: "chain resolved by repetition: A decides x, x leaves one value of y for B, y filters C",
			descriptors: []*InputDescriptor{
				selectionDescriptor("C", "c", idField("y", "y")),
				selectionDescriptor("B", "b", idField("x", "x"), idField("y", "y")),
				selectionDescriptor("A", "a", idField("x", "x")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("c1", map[string]any{"kind": "c", "y": "p"}),
				selectionCredential("c2", map[string]any{"kind": "c", "y": "q"}),
				selectionCredential("b1", map[string]any{"kind": "b", "x": "2", "y": "p"}),
				selectionCredential("b2", map[string]any{"kind": "b", "x": "1", "y": "q"}),
				selectionCredential("a1", map[string]any{"kind": "a", "x": "1"}),
			},
			expected:         map[string]string{"A": "a1", "B": "b2", "C": "c2"},
			orderIndependent: true,
		},
		{
			name:             "external key no descriptor declares is skipped",
			descriptors:      []*InputDescriptor{provider, delegation},
			vcs:              []vc.VerifiableCredential{p1, p2, d1, d2},
			selection:        map[string]string{"patient_id": "123"},
			expected:         map[string]string{"provider": "P1", "delegation": "D1"},
			orderIndependent: true,
		},
		{
			name:             "external key that no credential carries leaves the descriptor without credential",
			descriptors:      []*InputDescriptor{provider},
			vcs:              []vc.VerifiableCredential{p1, p2},
			selection:        map[string]string{"ura": "9"},
			expected:         map[string]string{"provider": ""},
			expectedReasons:  map[string][]string{"provider": {"ura"}},
			orderIndependent: true,
		},
		{
			name:             "external key leaving several matches that agree on all declared ids: first is used",
			descriptors:      []*InputDescriptor{delegation},
			vcs:              []vc.VerifiableCredential{d1, d2, d2copy},
			selection:        map[string]string{"ura": "2"},
			expected:         map[string]string{"delegation": "D2"},
			orderIndependent: true,
		},
		{
			name:             "without external keys differing matches give the first match that fits",
			descriptors:      []*InputDescriptor{provider, delegation},
			vcs:              []vc.VerifiableCredential{p1, p2, d1, d1b},
			expected:         map[string]string{"provider": "P1", "delegation": "D1"},
			orderIndependent: true,
		},
		{
			name:        "first-match binding: two unpinned descriptors sharing an id agree",
			descriptors: []*InputDescriptor{provider, delegation},
			// D2 is the first delegation in the wallet, but the provider (first open descriptor) takes P1.
			vcs:      []vc.VerifiableCredential{p1, p2, d2, d1},
			expected: map[string]string{"provider": "P1", "delegation": "D1"},
		},
		{
			name:        "first-match binding: the pick of the first open descriptor filters the others, also in reverse PD order",
			descriptors: []*InputDescriptor{delegation, provider},
			// The delegation is now the first open descriptor and takes D2; the provider follows.
			vcs:      []vc.VerifiableCredential{p1, p2, d2, d1},
			expected: map[string]string{"provider": "P2", "delegation": "D2"},
		},
		{
			name:        "first-match binding without partner: no backtracking, the other descriptor gets no credential",
			descriptors: []*InputDescriptor{provider, delegation},
			// The provider takes P1 (ura 1), for which there is no delegation.
			vcs:             []vc.VerifiableCredential{p1, p2, d2, d2b, d3},
			expected:        map[string]string{"provider": "P1", "delegation": ""},
			expectedReasons: map[string][]string{"delegation": {"ura"}},
		},
		{
			name: "descriptors decided in the same round that disagree: the first in PD order keeps its credential",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("x", "x")),
				selectionDescriptor("B", "b", idField("x", "x")),
				selectionDescriptor("C", "c", idField("z", "z")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "x": "1"}),
				selectionCredential("b1", map[string]any{"kind": "b", "x": "2"}),
				selectionCredential("c1", map[string]any{"kind": "c", "z": "1"}),
			},
			expected:        map[string]string{"A": "a1", "B": "", "C": "c1"},
			expectedReasons: map[string][]string{"B": {"x"}},
		},
		{
			name: "descriptors decided in the same round that disagree, other PD order: the first in PD order keeps its credential",
			descriptors: []*InputDescriptor{
				selectionDescriptor("B", "b", idField("x", "x")),
				selectionDescriptor("C", "c", idField("z", "z")),
				selectionDescriptor("A", "a", idField("x", "x")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "x": "1"}),
				selectionCredential("b1", map[string]any{"kind": "b", "x": "2"}),
				selectionCredential("c1", map[string]any{"kind": "c", "z": "1"}),
			},
			expected:        map[string]string{"A": "", "B": "b1", "C": "c1"},
			expectedReasons: map[string][]string{"A": {"x"}},
		},
		{
			name: "optional field that does not resolve is rejected by an external key",
			descriptors: []*InputDescriptor{
				selectionDescriptor("delegation", "delegation", optionalIDField("employee", "employee")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("no_employee", map[string]any{"kind": "delegation"}),
				d1b,
			},
			selection:        map[string]string{"employee": "e2"},
			expected:         map[string]string{"delegation": "D1b"},
			orderIndependent: true,
		},
		{
			name: "optional field that does not resolve agrees with a value selected inside the PD",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("site", "site")),
				selectionDescriptor("B", "b", optionalIDField("site", "site")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "site": "s1"}),
				selectionCredential("b_other_site", map[string]any{"kind": "b", "site": "s2"}),
				selectionCredential("b_no_site", map[string]any{"kind": "b"}),
			},
			expected:         map[string]string{"A": "a1", "B": "b_no_site"},
			orderIndependent: true,
		},
		{
			name: "optional field that does not resolve adds nothing to the map",
			descriptors: []*InputDescriptor{
				selectionDescriptor("B", "b", optionalIDField("site", "site")),
				selectionDescriptor("C", "c", idField("site", "site")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("b_no_site", map[string]any{"kind": "b"}),
				selectionCredential("c1", map[string]any{"kind": "c", "site": "s2"}),
				selectionCredential("c2", map[string]any{"kind": "c", "site": "s1"}),
			},
			// B is decided first; had it added a value for site, C would have been filtered.
			expected:         map[string]string{"B": "b_no_site", "C": "c1"},
			orderIndependent: true,
		},
		{
			name: "descriptors sharing an id that resolves to arrays get equal arrays",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
				selectionDescriptor("B", "b", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x", "y"}}),
				selectionCredential("b1", map[string]any{"kind": "b", "tags": []any{"y", "x"}}),
				selectionCredential("b2", map[string]any{"kind": "b", "tags": []any{"x", "y"}}),
			},
			expected:         map[string]string{"A": "a1", "B": "b2"},
			orderIndependent: true,
		},
		{
			name: "descriptors sharing an id that resolves to objects get equal objects",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("org", "org")),
				selectionDescriptor("B", "b", idField("org", "org")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "org": map[string]any{"ura": "1", "name": "Org A"}}),
				selectionCredential("b1", map[string]any{"kind": "b", "org": map[string]any{"ura": "2", "name": "Org B"}}),
				selectionCredential("b2", map[string]any{"kind": "b", "org": map[string]any{"name": "Org A", "ura": "1"}}),
			},
			expected:         map[string]string{"A": "a1", "B": "b2"},
			orderIndependent: true,
		},
		{
			name: "array and scalar disagree",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
				selectionDescriptor("B", "b", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x"}}),
				selectionCredential("b_scalar", map[string]any{"kind": "b", "tags": "x"}),
				selectionCredential("b_array", map[string]any{"kind": "b", "tags": []any{"x"}}),
			},
			expected:         map[string]string{"A": "a1", "B": "b_array"},
			orderIndependent: true,
		},
		{
			name: "scalar whose text looks like JSON does not equal an array",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
				selectionDescriptor("B", "b", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x"}}),
				selectionCredential("b1", map[string]any{"kind": "b", "tags": `["x"]`}),
			},
			expected:        map[string]string{"A": "a1", "B": ""},
			expectedReasons: map[string][]string{"B": {"tags"}},
		},
		{
			name: "descriptors decided in the same round with different arrays: the first in PD order keeps its credential",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
				selectionDescriptor("B", "b", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x"}}),
				selectionCredential("b1", map[string]any{"kind": "b", "tags": []any{"y"}}),
			},
			expected:        map[string]string{"A": "a1", "B": ""},
			expectedReasons: map[string][]string{"B": {"tags"}},
		},
		{
			name: "array picked by the first open descriptor filters the others",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
				selectionDescriptor("B", "b", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x"}}),
				selectionCredential("a2", map[string]any{"kind": "a", "tags": []any{"y"}}),
				selectionCredential("b1", map[string]any{"kind": "b", "tags": []any{"y"}}),
				selectionCredential("b2", map[string]any{"kind": "b", "tags": []any{"x"}}),
			},
			expected: map[string]string{"A": "a1", "B": "b2"},
		},
		{
			name: "array value never matches an external key",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "tags": []any{"x"}}),
			},
			selection:        map[string]string{"tags": "x"},
			expected:         map[string]string{"A": ""},
			expectedReasons:  map[string][]string{"A": {"tags"}},
			orderIndependent: true,
		},
		{
			name: "numbers and booleans are compared as text",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("floor", "floor"), idField("active", "active")),
				selectionDescriptor("B", "b", idField("floor", "floor"), idField("active", "active")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "floor": float64(3), "active": true}),
				selectionCredential("b1", map[string]any{"kind": "b", "floor": "4", "active": "true"}),
				selectionCredential("b2", map[string]any{"kind": "b", "floor": "3", "active": "false"}),
				selectionCredential("b3", map[string]any{"kind": "b", "floor": "3", "active": "true"}),
			},
			selection:        map[string]string{"active": "true"},
			expected:         map[string]string{"A": "a1", "B": "b3"},
			orderIndependent: true,
		},
	}
	for _, tc := range testCases {
		orders := [][]*InputDescriptor{tc.descriptors}
		if tc.orderIndependent {
			orders = permutations(tc.descriptors)
		}
		for _, descriptors := range orders {
			var order []string
			for _, descriptor := range descriptors {
				order = append(order, descriptor.Id)
			}
			t.Run(tc.name+" (order: "+strings.Join(order, ", ")+")", func(t *testing.T) {
				pd := PresentationDefinition{InputDescriptors: descriptors}

				candidates, reasons, err := pd.selectCredentials(tc.vcs, tc.selection, nil)

				require.NoError(t, err)
				require.Len(t, candidates, len(descriptors))
				for i, candidate := range candidates {
					assert.Equal(t, descriptors[i].Id, candidate.InputDescriptor.Id, "candidates follow the order of the input descriptors")
				}
				assert.Equal(t, tc.expected, selectedCredentialIDs(candidates))
				require.Len(t, reasons, len(descriptors))
				actualReasons := make(map[string]string)
				for i, reason := range reasons {
					if reason != "" {
						actualReasons[descriptors[i].Id] = reason
					}
				}
				for descriptorID, expectedTexts := range tc.expectedReasons {
					for _, expectedText := range expectedTexts {
						assert.Contains(t, actualReasons[descriptorID], expectedText)
					}
				}
				assert.Len(t, actualReasons, len(tc.expectedReasons))
			})
		}
	}
}

func TestPresentationDefinition_selectCredentials_EdgeCases(t *testing.T) {
	t.Run("empty (null) input descriptor is an error, not a panic", func(t *testing.T) {
		pd := PresentationDefinition{InputDescriptors: []*InputDescriptor{
			selectionDescriptor("A", "a"),
			nil,
		}}

		_, _, err := pd.selectCredentials([]vc.VerifiableCredential{selectionCredential("a1", map[string]any{"kind": "a"})}, nil, nil)

		assert.EqualError(t, err, "input descriptor at index 1 of the presentation definition is empty")
	})
	t.Run("explanations follow the position of the input descriptor, also when ids are duplicated", func(t *testing.T) {
		pd := PresentationDefinition{InputDescriptors: []*InputDescriptor{
			selectionDescriptor("dup", "a", idField("x", "x")),
			selectionDescriptor("dup", "b", idField("x", "x")),
		}}
		vcs := []vc.VerifiableCredential{
			selectionCredential("a1", map[string]any{"kind": "a", "x": "1"}),
			selectionCredential("b1", map[string]any{"kind": "b", "x": "2"}),
		}

		candidates, reasons, err := pd.selectCredentials(vcs, nil, nil)

		require.NoError(t, err)
		require.NotNil(t, candidates[0].VC)
		assert.Nil(t, candidates[1].VC)
		assert.Empty(t, reasons[0])
		assert.Contains(t, reasons[1], "x")
	})
}

func TestPresentationDefinition_selectCredentials_MultipleCredentials(t *testing.T) {
	testCases := []struct {
		name          string
		descriptors   []*InputDescriptor
		vcs           []vc.VerifiableCredential
		selection     map[string]string
		expectedTexts []string
	}{
		{
			name: "external key leaving matches that differ on another declared id",
			descriptors: []*InputDescriptor{
				selectionDescriptor("delegation", "delegation", idField("ura", "ura"), idField("employee", "employee")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"}),
				selectionCredential("D2b", map[string]any{"kind": "delegation", "ura": "2", "employee": "e2"}),
			},
			selection:     map[string]string{"ura": "2"},
			expectedTexts: []string{"input descriptor 'delegation'", "selected field id(s) ura", "differ on field id(s) employee"},
		},
		{
			name: "a field that does not resolve differs from one that does",
			descriptors: []*InputDescriptor{
				selectionDescriptor("delegation", "delegation", idField("ura", "ura"), optionalIDField("site", "site")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2"}),
				selectionCredential("D2site", map[string]any{"kind": "delegation", "ura": "2", "site": "s1"}),
			},
			selection:     map[string]string{"ura": "2"},
			expectedTexts: []string{"input descriptor 'delegation'", "differ on field id(s) site"},
		},
		{
			name: "arrays that differ make matches differ",
			descriptors: []*InputDescriptor{
				selectionDescriptor("A", "a", idField("ura", "ura"), idField("tags", "tags")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("a1", map[string]any{"kind": "a", "ura": "2", "tags": []any{"x"}}),
				selectionCredential("a2", map[string]any{"kind": "a", "ura": "2", "tags": []any{"y"}}),
			},
			selection:     map[string]string{"ura": "2"},
			expectedTexts: []string{"input descriptor 'A'", "differ on field id(s) tags"},
		},
		{
			name: "open descriptor with an external key fails, even when another open descriptor could pick first",
			descriptors: []*InputDescriptor{
				selectionDescriptor("provider", "provider", idField("ura", "ura")),
				selectionDescriptor("delegation", "delegation", idField("ura", "ura"), idField("employee", "employee")),
			},
			vcs: []vc.VerifiableCredential{
				selectionCredential("P1", map[string]any{"kind": "provider", "ura": "1"}),
				selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2"}),
				selectionCredential("D1", map[string]any{"kind": "delegation", "ura": "1", "employee": "e1"}),
				selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"}),
			},
			selection:     map[string]string{"employee": "e1"},
			expectedTexts: []string{"input descriptor 'delegation'", "selected field id(s) employee", "differ on field id(s) ura"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pd := PresentationDefinition{InputDescriptors: tc.descriptors}

			_, _, err := pd.selectCredentials(tc.vcs, tc.selection, nil)

			require.ErrorIs(t, err, ErrMultipleCredentials)
			for _, expectedText := range tc.expectedTexts {
				assert.ErrorContains(t, err, expectedText)
			}
		})
	}
}

func TestPresentationDefinition_selectCredentials_IsDeterministic(t *testing.T) {
	// Go randomizes map iteration; repeat a case with many ids to make sure the result never depends on it.
	descriptors := []*InputDescriptor{
		selectionDescriptor("A", "a", idField("v", "v"), idField("w", "w"), idField("x", "x")),
		selectionDescriptor("B", "b", idField("w", "w"), idField("x", "x"), idField("y", "y")),
		selectionDescriptor("C", "c", idField("x", "x"), idField("y", "y"), idField("z", "z")),
	}
	vcs := []vc.VerifiableCredential{
		selectionCredential("a1", map[string]any{"kind": "a", "v": "1", "w": "1", "x": "1"}),
		selectionCredential("a2", map[string]any{"kind": "a", "v": "2", "w": "2", "x": "2"}),
		selectionCredential("b1", map[string]any{"kind": "b", "w": "2", "x": "2", "y": "1"}),
		selectionCredential("b2", map[string]any{"kind": "b", "w": "1", "x": "1", "y": "2"}),
		selectionCredential("c1", map[string]any{"kind": "c", "x": "2", "y": "1", "z": "1"}),
		selectionCredential("c2", map[string]any{"kind": "c", "x": "1", "y": "2", "z": "2"}),
	}
	pd := PresentationDefinition{InputDescriptors: descriptors}
	for i := 0; i < 50; i++ {
		candidates, _, err := pd.selectCredentials(vcs, nil, nil)

		require.NoError(t, err)
		require.Equal(t, map[string]string{"A": "a1", "B": "b2", "C": "c2"}, selectedCredentialIDs(candidates))
	}
}

func TestPresentationDefinition_MatchWithSelection(t *testing.T) {
	vc1 := selectionCredential("1", map[string]any{"patientId": "123"})
	vc2 := selectionCredential("2", map[string]any{"patientId": "456"})
	vc3 := selectionCredential("3", map[string]any{"patientId": "456"})
	patientPD := PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{Id: "patient_credential", Constraints: &Constraints{Fields: []Field{idField("patient_id", "patientId")}}},
		},
	}
	enrollmentPD := PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{Id: "enrollment", Constraints: &Constraints{Fields: []Field{idField("patient_id", "patientId"), idField("org_city", "city")}}},
		},
	}
	multiPD := PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{Id: "org_credential", Constraints: &Constraints{Fields: []Field{idField("ura", "ura")}}},
			{Id: "patient_enrollment", Constraints: &Constraints{Fields: []Field{idField("bsn", "bsn")}}},
		},
	}
	uraA := selectionCredential("A", map[string]any{"ura": "URA-001"})
	uraB := selectionCredential("B", map[string]any{"ura": "URA-002"})
	bsnC := selectionCredential("C", map[string]any{"bsn": "BSN-111"})
	bsnD := selectionCredential("D", map[string]any{"bsn": "BSN-222"})
	testCases := []struct {
		name      string
		pd        PresentationDefinition
		vcs       []vc.VerifiableCredential
		selection map[string]string
		// expected are the ids of the returned credentials, in order.
		expected    []string
		expectedErr error
		errTexts    []string
	}{
		{
			name:      "selection picks the right credential by field value",
			pd:        patientPD,
			vcs:       []vc.VerifiableCredential{vc1, vc2},
			selection: map[string]string{"patient_id": "456"},
			expected:  []string{"2"},
		},
		{
			name:        "no credential has the selected value: ErrNoCredentials naming the descriptor and the id",
			pd:          patientPD,
			vcs:         []vc.VerifiableCredential{vc1, vc2},
			selection:   map[string]string{"patient_id": "nonexistent"},
			expectedErr: ErrNoCredentials,
			errTexts:    []string{"patient_credential", "patient_id"},
		},
		{
			// Before, any selection leaving more than one credential failed with ErrMultipleCredentials.
			name:      "several credentials that agree on all declared ids: first is used",
			pd:        patientPD,
			vcs:       []vc.VerifiableCredential{vc2, vc3},
			selection: map[string]string{"patient_id": "456"},
			expected:  []string{"2"},
		},
		{
			name: "credentials that differ on another declared id: ErrMultipleCredentials naming the descriptor and ids",
			pd:   enrollmentPD,
			vcs: []vc.VerifiableCredential{
				selectionCredential("A", map[string]any{"patientId": "123", "city": "Amsterdam"}),
				selectionCredential("B", map[string]any{"patientId": "123", "city": "Rotterdam"}),
			},
			selection:   map[string]string{"patient_id": "123"},
			expectedErr: ErrMultipleCredentials,
			errTexts:    []string{"enrollment", "patient_id", "org_city"},
		},
		{
			name: "matches numeric field values",
			pd: PresentationDefinition{InputDescriptors: []*InputDescriptor{
				{Id: "room_access", Constraints: &Constraints{Fields: []Field{idField("floor", "floor")}}},
			}},
			vcs: []vc.VerifiableCredential{
				selectionCredential("A", map[string]any{"floor": float64(1)}),
				selectionCredential("B", map[string]any{"floor": float64(3)}),
			},
			selection: map[string]string{"floor": "3"},
			expected:  []string{"B"},
		},
		{
			// The presentation definition defines which values matter: credentials that differ only in fields
			// without an id are interchangeable.
			name: "credentials that differ only in fields without id: first is used",
			pd:   patientPD,
			vcs: []vc.VerifiableCredential{
				selectionCredential("granted", map[string]any{"patientId": "456", "consentStatus": true}),
				selectionCredential("withdrawn", map[string]any{"patientId": "456", "consentStatus": false}),
			},
			selection: map[string]string{"patient_id": "456"},
			expected:  []string{"granted"},
		},
		{
			name: "matches boolean field values",
			pd: PresentationDefinition{InputDescriptors: []*InputDescriptor{
				{Id: "consent", Constraints: &Constraints{Fields: []Field{idField("granted", "granted")}}},
			}},
			vcs: []vc.VerifiableCredential{
				selectionCredential("A", map[string]any{"granted": true}),
				selectionCredential("B", map[string]any{"granted": false}),
			},
			selection: map[string]string{"granted": "false"},
			expected:  []string{"B"},
		},
		{
			// An empty value is a selection like any other: it does not mean "no selection".
			name: "empty selection value only selects a field that is an empty string",
			pd:   patientPD,
			vcs: []vc.VerifiableCredential{
				vc1,
				selectionCredential("empty", map[string]any{"patientId": ""}),
			},
			selection: map[string]string{"patient_id": ""},
			expected:  []string{"empty"},
		},
		{
			name:        "empty selection value no credential has: ErrNoCredentials",
			pd:          patientPD,
			vcs:         []vc.VerifiableCredential{vc1, vc2},
			selection:   map[string]string{"patient_id": ""},
			expectedErr: ErrNoCredentials,
			errTexts:    []string{"patient_credential", "patient_id"},
		},
		{
			// A selected value is strict: a credential on which the (optional) field does not resolve never has it.
			// Credentials without the field must not count as several differing matches either.
			name: "selected optional field that resolves on no credential: ErrNoCredentials, not ErrMultipleCredentials",
			pd: PresentationDefinition{InputDescriptors: []*InputDescriptor{
				{Id: "patient_credential", Constraints: &Constraints{Fields: []Field{optionalIDField("patient_id", "patientId")}}},
			}},
			vcs: []vc.VerifiableCredential{
				selectionCredential("A", map[string]any{"name": "x"}),
				selectionCredential("B", map[string]any{"name": "y"}),
			},
			selection:   map[string]string{"patient_id": "456"},
			expectedErr: ErrNoCredentials,
			errTexts:    []string{"patient_credential", "patient_id"},
		},
		{
			name:      "selection key the PD does not declare is skipped",
			pd:        patientPD,
			vcs:       []vc.VerifiableCredential{vc1, vc2},
			selection: map[string]string{"nonexistent_field": "value"},
			expected:  []string{"1"},
		},
		{
			name:      "undeclared selection key does not affect declared keys",
			pd:        patientPD,
			vcs:       []vc.VerifiableCredential{vc1, vc2},
			selection: map[string]string{"patient_id": "456", "nonexistent_field": "value"},
			expected:  []string{"2"},
		},
		{
			name:      "descriptor without selection keys uses its first match",
			pd:        multiPD,
			vcs:       []vc.VerifiableCredential{uraA, uraB, bsnC, bsnD},
			selection: map[string]string{"bsn": "BSN-222"},
			expected:  []string{"A", "D"},
		},
		{
			name: "multiple selection keys use AND semantics",
			pd:   enrollmentPD,
			vcs: []vc.VerifiableCredential{
				selectionCredential("A", map[string]any{"patientId": "123", "city": "Amsterdam"}),
				selectionCredential("B", map[string]any{"patientId": "123", "city": "Rotterdam"}),
			},
			selection: map[string]string{"patient_id": "123", "org_city": "Rotterdam"},
			expected:  []string{"B"},
		},
		{
			name:      "multiple descriptors with independent selection keys",
			pd:        multiPD,
			vcs:       []vc.VerifiableCredential{uraA, uraB, bsnC, bsnD},
			selection: map[string]string{"ura": "URA-002", "bsn": "BSN-111"},
			expected:  []string{"B", "C"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vcs, mappings, err := tc.pd.MatchWithSelection(tc.vcs, tc.selection)

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
				for _, text := range tc.errTexts {
					assert.ErrorContains(t, err, text)
				}
				return
			}
			require.NoError(t, err)
			var actual []string
			for _, credential := range vcs {
				actual = append(actual, credential.ID.String())
			}
			assert.Equal(t, tc.expected, actual)
			assert.Len(t, mappings, len(tc.expected))
		})
	}
}

func TestPresentationDefinition_MatchWithSelection_SubmissionRequirementsAndSharedIDs(t *testing.T) {
	// The provider is selected (Org A, ura 1), the wallet only has delegations for ura 2 and 3: the provider's
	// ura filters the delegation descriptor, which is left without credential. The submission requirements decide
	// whether that is acceptable.
	wallet := []vc.VerifiableCredential{
		selectionCredential("P1", map[string]any{"kind": "provider", "ura": "1", "name": "Org A"}),
		selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2", "name": "Org B"}),
		selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2"}),
		selectionCredential("D3", map[string]any{"kind": "delegation", "ura": "3"}),
	}
	pdWithDelegationRule := func(rule SubmissionRequirement) PresentationDefinition {
		provider := selectionDescriptor("provider", "provider", idField("ura", "ura"), idField("org_name", "name"))
		provider.Group = []string{"provider"}
		delegation := selectionDescriptor("delegation", "delegation", idField("ura", "ura"))
		delegation.Group = []string{"delegation"}
		rule.From = "delegation"
		return PresentationDefinition{
			InputDescriptors: []*InputDescriptor{provider, delegation},
			SubmissionRequirements: []*SubmissionRequirement{
				{Rule: "all", From: "provider"},
				&rule,
			},
		}
	}
	selection := map[string]string{"org_name": "Org A"}

	t.Run("pick rule with min 0 accepts the descriptor without credential", func(t *testing.T) {
		zero := 0
		pd := pdWithDelegationRule(SubmissionRequirement{Rule: "pick", Min: &zero})

		vcs, mappings, err := pd.MatchWithSelection(wallet, selection)

		require.NoError(t, err)
		require.Len(t, vcs, 1)
		assert.Equal(t, "P1", vcs[0].ID.String())
		require.Len(t, mappings, 1)
		assert.Equal(t, "provider", mappings[0].Id)
	})
	t.Run("all rule fails with ErrNoCredentials", func(t *testing.T) {
		pd := pdWithDelegationRule(SubmissionRequirement{Rule: "all"})

		_, _, err := pd.MatchWithSelection(wallet, selection)

		assert.ErrorIs(t, err, ErrNoCredentials)
	})
	t.Run("pick alternatives that share an id: the first in PD order is used", func(t *testing.T) {
		// Two input descriptors ask for the same credential in two formats and declare the same id; a pick rule
		// takes one. The wallet holds one credential of each, with differing values: only one is presented, so
		// that must not fail.
		asJSONLD := selectionDescriptor("as_jsonld", "jsonld", idField("organization_name", "name"))
		asJSONLD.Group = []string{"g"}
		asJWT := selectionDescriptor("as_jwt", "jwt", idField("organization_name", "name"))
		asJWT.Group = []string{"g"}
		one := 1
		pd := PresentationDefinition{
			InputDescriptors:       []*InputDescriptor{asJSONLD, asJWT},
			SubmissionRequirements: []*SubmissionRequirement{{Rule: "pick", Count: &one, From: "g"}},
		}
		vcs := []vc.VerifiableCredential{
			selectionCredential("A", map[string]any{"kind": "jsonld", "name": "Care B.V."}),
			selectionCredential("B", map[string]any{"kind": "jwt", "name": "Care BV"}),
		}

		selected, mappings, err := pd.Match(vcs)

		require.NoError(t, err)
		require.Len(t, selected, 1)
		assert.Equal(t, "A", selected[0].ID.String())
		require.Len(t, mappings, 1)
		assert.Equal(t, "as_jsonld", mappings[0].Id)
	})
	t.Run("selected value leaving differing credentials fails, also for a descriptor a pick rule may leave out", func(t *testing.T) {
		// A pick rule with min 0 decides whether a descriptor without credential is acceptable, not which of several
		// differing credentials the caller meant: leaving the descriptor out would silently ignore the selection.
		provider := selectionDescriptor("provider", "provider", idField("ura", "ura"))
		provider.Group = []string{"provider"}
		delegation := selectionDescriptor("delegation", "delegation", idField("ura", "ura"), idField("employee", "employee"))
		delegation.Group = []string{"delegation"}
		zero := 0
		one := 1
		pd := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{provider, delegation},
			SubmissionRequirements: []*SubmissionRequirement{
				{Rule: "all", From: "provider"},
				{Rule: "pick", From: "delegation", Min: &zero, Max: &one},
			},
		}
		vcs := []vc.VerifiableCredential{
			selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2"}),
			selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"}),
			selectionCredential("D2b", map[string]any{"kind": "delegation", "ura": "2", "employee": "e2"}),
		}

		_, _, err := pd.MatchWithSelection(vcs, map[string]string{"ura": "2"})

		require.ErrorIs(t, err, ErrMultipleCredentials)
		assert.ErrorContains(t, err, "input descriptor 'delegation'")
		assert.ErrorContains(t, err, "employee")
	})
	t.Run("one credential that fulfills two descriptors of a pick 1 group is presented once", func(t *testing.T) {
		// The pick rule counts credentials: a credential matching several descriptors of the group must not be
		// presented for more of them than the rule allows.
		first := &InputDescriptor{Id: "first", Group: []string{"g"}, Constraints: &Constraints{Fields: []Field{idField("f1", "f1")}}}
		second := &InputDescriptor{Id: "second", Group: []string{"g"}, Constraints: &Constraints{Fields: []Field{idField("f2", "f2")}}}
		one := 1
		pd := PresentationDefinition{
			InputDescriptors:       []*InputDescriptor{first, second},
			SubmissionRequirements: []*SubmissionRequirement{{Rule: "pick", Count: &one, From: "g"}},
		}

		selected, mappings, err := pd.Match([]vc.VerifiableCredential{selectionCredential("both", map[string]any{"f1": "x", "f2": "y"})})

		require.NoError(t, err)
		require.Len(t, selected, 1)
		assert.Equal(t, "both", selected[0].ID.String())
		require.Len(t, mappings, 1)
		assert.Equal(t, "first", mappings[0].Id)
	})
	t.Run("required descriptors that conflict: ErrNoCredentials naming the descriptor and the id", func(t *testing.T) {
		pd := PresentationDefinition{InputDescriptors: []*InputDescriptor{
			selectionDescriptor("as_jsonld", "jsonld", idField("organization_name", "name")),
			selectionDescriptor("as_jwt", "jwt", idField("organization_name", "name")),
		}}
		vcs := []vc.VerifiableCredential{
			selectionCredential("A", map[string]any{"kind": "jsonld", "name": "Care B.V."}),
			selectionCredential("B", map[string]any{"kind": "jwt", "name": "Care BV"}),
		}

		_, _, err := pd.Match(vcs)

		require.ErrorIs(t, err, ErrNoCredentials)
		assert.ErrorContains(t, err, "no VC for InputDescriptor (as_jwt): no matching credential has the selected value for field id(s) organization_name")
	})
}
