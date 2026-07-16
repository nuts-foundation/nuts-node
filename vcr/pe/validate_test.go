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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustParsePD unmarshals a presentation definition from its JSON wire form. JSON keeps the
// deeply-nested PDs readable; DisallowUnknownFields turns a misspelled key into a loud error.
func mustParsePD(t *testing.T, jsonStr string) PresentationDefinition {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.DisallowUnknownFields()
	var pd PresentationDefinition
	require.NoError(t, dec.Decode(&pd))
	return pd
}

func TestValidateSelectionKeys(t *testing.T) {
	singlePD := `{
		"id": "single-pd",
		"input_descriptors": [{
			"id": "patient",
			"constraints": {"fields": [
				{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]},
				{"path": ["$.type"], "filter": {"type": "string", "const": "PatientCredential"}}
			]}
		}]
	}`
	spPD := `{
		"id": "sp-pd",
		"input_descriptors": [{
			"id": "delegation",
			"constraints": {"fields": [{"id": "sp_did", "path": ["$.credentialSubject.id"]}]}
		}]
	}`

	t.Run("all keys known passes", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"patient_bsn": "999911234"}, mustParsePD(t, singlePD))

		assert.NoError(t, err)
	})

	t.Run("unknown key against a single PD is reported", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"favourite_color": "blue"}, mustParsePD(t, singlePD))

		var unknownErr *UnknownSelectionKeysError
		require.ErrorAs(t, err, &unknownErr)
		assert.Equal(t, []string{"favourite_color"}, unknownErr.Keys)
		assert.EqualError(t, err, "unknown credential_selection keys: favourite_color")
	})

	t.Run("key targeting one side of a two-PD union passes", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"patient_bsn": "999911234", "sp_did": "did:web:sp"},
			mustParsePD(t, singlePD), mustParsePD(t, spPD))

		assert.NoError(t, err)
	})

	t.Run("unknown key is validated against the union, not each PD independently", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"org_urra": "1"},
			mustParsePD(t, singlePD), mustParsePD(t, spPD))

		var unknownErr *UnknownSelectionKeysError
		require.ErrorAs(t, err, &unknownErr)
		assert.Equal(t, []string{"org_urra"}, unknownErr.Keys)
	})

	t.Run("empty-string values are validated by name only", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"patient_bsn": ""}, mustParsePD(t, singlePD))

		assert.NoError(t, err)
	})

	t.Run("multiple unknown keys are all listed, sorted", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"zeta": "1", "alpha": "2", "patient_bsn": "3"},
			mustParsePD(t, singlePD))

		var unknownErr *UnknownSelectionKeysError
		require.ErrorAs(t, err, &unknownErr)
		assert.Equal(t, []string{"alpha", "zeta"}, unknownErr.Keys)
	})

	t.Run("no PDs supplied makes every key unknown", func(t *testing.T) {
		err := ValidateSelectionKeys(map[string]string{"patient_bsn": "999911234"})

		var unknownErr *UnknownSelectionKeysError
		require.ErrorAs(t, err, &unknownErr)
		assert.Equal(t, []string{"patient_bsn"}, unknownErr.Keys)
	})

	t.Run("nil selection passes", func(t *testing.T) {
		assert.NoError(t, ValidateSelectionKeys(nil, mustParsePD(t, singlePD)))
	})
}

// twoFieldPD builds a PD with two descriptors, each carrying one field with the given id and
// filter JSON (empty filter string means no filter). Most same-id consistency cases fit this shape.
func twoFieldPD(t *testing.T, id string, filterA string, filterB string) PresentationDefinition {
	t.Helper()
	field := func(filter string) string {
		if filter == "" {
			return `{"id": "` + id + `", "path": ["$.credentialSubject.a"]}`
		}
		return `{"id": "` + id + `", "path": ["$.credentialSubject.a"], "filter": ` + filter + `}`
	}
	return mustParsePD(t, `{
		"id": "test-pd",
		"input_descriptors": [
			{"id": "d1", "constraints": {"fields": [`+field(filterA)+`]}},
			{"id": "d2", "constraints": {"fields": [`+field(filterB)+`]}}
		]
	}`)
}

// conflictKinds maps FieldID to the conflict kinds reported for it.
func conflictKinds(t *testing.T, err error) map[string][]ConflictKind {
	t.Helper()
	var pdErr *PDValidationError
	require.ErrorAs(t, err, &pdErr)
	kinds := make(map[string][]ConflictKind)
	for _, conflict := range pdErr.Conflicts {
		kinds[conflict.FieldID] = append(kinds[conflict.FieldID], conflict.Kind)
	}
	return kinds
}

func TestValidate_Duplicates(t *testing.T) {
	t.Run("duplicate field id within one constraints object", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "d1",
				"constraints": {"fields": [
					{"id": "org_ura", "path": ["$.credentialSubject.ura"]},
					{"id": "org_ura", "path": ["$.credentialSubject.organization.ura"]}
				]}
			}]
		}`)

		kinds := conflictKinds(t, Validate(pd))
		assert.Equal(t, []ConflictKind{ConflictDuplicate}, kinds["org_ura"])
	})

	t.Run("same id across descriptors is not a duplicate", func(t *testing.T) {
		assert.NoError(t, Validate(twoFieldPD(t, "org_ura", "", "")))
	})

	t.Run("duplicate input descriptor ids", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "d1", "constraints": {"fields": [{"path": ["$.a"]}]}},
				{"id": "d1", "constraints": {"fields": [{"path": ["$.b"]}]}}
			]
		}`)

		kinds := conflictKinds(t, Validate(pd))
		assert.Equal(t, []ConflictKind{ConflictDuplicate}, kinds["d1"])
	})
}

func TestValidate_SameIDConsistency(t *testing.T) {
	t.Run("conflicting filter types", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "org_ura",
			`{"type": "string", "pattern": "^\\d{8}$"}`,
			`{"type": "number"}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictType}, kinds["org_ura"])
		assert.ErrorContains(t, err, "number")
		assert.ErrorContains(t, err, "string")
	})

	t.Run("enum forces string matching, so enum vs type number conflicts", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "enum": ["a"]}`,
			`{"type": "number"}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictType}, kinds["x"])
	})

	t.Run("differing consts", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "const": "A"}`,
			`{"type": "string", "const": "B"}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictUnsatisfiable}, kinds["x"])
	})

	t.Run("const not in enum", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "const": "Z"}`,
			`{"type": "string", "enum": ["A", "B"]}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictUnsatisfiable}, kinds["x"])
	})

	t.Run("disjoint enums", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "enum": ["A", "B"]}`,
			`{"type": "string", "enum": ["C"]}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictUnsatisfiable}, kinds["x"])
	})

	t.Run("const failing another field's pattern", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "const": "99991123"}`,
			`{"type": "string", "pattern": "^\\d{9}$"}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictUnsatisfiable}, kinds["x"])
	})

	t.Run("enum with no member matching another field's pattern", func(t *testing.T) {
		err := Validate(twoFieldPD(t, "x",
			`{"type": "string", "enum": ["GRANTED", "WITHDRAWN"]}`,
			`{"type": "string", "pattern": "^[a-z]+$"}`))

		kinds := conflictKinds(t, err)
		assert.Equal(t, []ConflictKind{ConflictUnsatisfiable}, kinds["x"])
	})

	t.Run("allowed: overlapping value sets", func(t *testing.T) {
		assert.NoError(t, Validate(twoFieldPD(t, "x",
			`{"type": "string", "const": "granted"}`,
			`{"type": "string", "enum": ["granted", "withdrawn"]}`)))
	})

	t.Run("allowed: path-only difference, no filters", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "d1", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.id"]}]}},
				{"id": "d2", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.issuedTo"]}]}}
			]
		}`)
		assert.NoError(t, Validate(pd))
	})

	t.Run("allowed: matching type-only filters", func(t *testing.T) {
		assert.NoError(t, Validate(twoFieldPD(t, "x",
			`{"type": "string"}`,
			`{"type": "string"}`)))
	})

	t.Run("allowed: single occurrence with a filter", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "d1",
				"constraints": {"fields": [{"id": "x", "path": ["$.a"], "filter": {"type": "string", "const": "A"}}]}
			}]
		}`)
		assert.NoError(t, Validate(pd))
	})

	t.Run("deferred: pattern versus pattern", func(t *testing.T) {
		// two compilable patterns with an empty intersection are not detected at load;
		// this degrades to a request-time no-match, surfaced by the MatchReport
		assert.NoError(t, Validate(twoFieldPD(t, "x",
			`{"type": "string", "pattern": "^a"}`,
			`{"type": "string", "pattern": "^b"}`)))
	})

	t.Run("multiple conflicts are aggregated and sorted", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "d1", "constraints": {"fields": [
					{"id": "zeta", "path": ["$.a"], "filter": {"type": "string", "const": "A"}},
					{"id": "alpha", "path": ["$.b"], "filter": {"type": "string"}}
				]}},
				{"id": "d2", "constraints": {"fields": [
					{"id": "zeta", "path": ["$.a"], "filter": {"type": "string", "const": "B"}},
					{"id": "alpha", "path": ["$.b"], "filter": {"type": "number"}}
				]}}
			]
		}`)

		err := Validate(pd)

		var pdErr *PDValidationError
		require.ErrorAs(t, err, &pdErr)
		require.Len(t, pdErr.Conflicts, 2)
		assert.Equal(t, "alpha", pdErr.Conflicts[0].FieldID)
		assert.Equal(t, ConflictType, pdErr.Conflicts[0].Kind)
		assert.Equal(t, "zeta", pdErr.Conflicts[1].FieldID)
		assert.Equal(t, ConflictUnsatisfiable, pdErr.Conflicts[1].Kind)
		assert.ErrorContains(t, err, "test-pd")
	})

	t.Run("descriptors without constraints are skipped", func(t *testing.T) {
		pd := mustParsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{"id": "d1"}, {"id": "d2"}]
		}`)
		assert.NoError(t, Validate(pd))
	})

	t.Run("empty PD is valid", func(t *testing.T) {
		assert.NoError(t, Validate(mustParsePD(t, `{"id": "empty", "input_descriptors": []}`)))
	})
}
