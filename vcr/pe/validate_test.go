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
