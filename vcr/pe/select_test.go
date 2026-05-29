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

	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePD unmarshals a presentation definition from its JSON wire form. JSON keeps the
// often deeply-nested PDs (input descriptors, constraints, submission requirements) readable.
// DisallowUnknownFields turns a misspelled key into a loud error instead of a silently dropped field.
func parsePD(t *testing.T, jsonStr string) PresentationDefinition {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.DisallowUnknownFields()
	var pd PresentationDefinition
	require.NoError(t, dec.Decode(&pd))
	return pd
}

// parseVC unmarshals a verifiable credential from its JSON wire form. Going through JSON gives
// the same runtime types the engine sees in production (notably JSON numbers become float64).
func parseVC(t *testing.T, jsonStr string) vc.VerifiableCredential {
	t.Helper()
	var cred vc.VerifiableCredential
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &cred))
	return cred
}

func TestSelect(t *testing.T) {
	t.Run("single descriptor with one matching candidate binds it", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {
					"fields": [{
						"id": "patient_id",
						"path": ["$.credentialSubject.patientId"]
					}]
				}
			}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		assert.Equal(t, "patient_credential", result.Candidates[0].InputDescriptor.Id)
		require.NotNil(t, result.Candidates[0].VC)
		require.NotNil(t, result.Candidates[0].VC.ID)
		assert.Equal(t, "vc-1", result.Candidates[0].VC.ID.String())
	})
}
