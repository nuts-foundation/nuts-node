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

	t.Run("required descriptor with zero matches returns ErrNoCredentials", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {
					"fields": [{
						"id": "patient_id",
						"path": ["$.credentialSubject.patientId"],
						"filter": {"type": "string", "const": "999"}
					}]
				}
			}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)

		_, err := Select(pd, []vc.VerifiableCredential{cred})

		assert.ErrorIs(t, err, ErrNoCredentials)
	})

	t.Run("multiple required descriptors all fill", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "org_credential", "constraints": {"fields": [{"id": "ura", "path": ["$.credentialSubject.ura"]}]}},
				{"id": "patient_enrollment", "constraints": {"fields": [{"id": "bsn", "path": ["$.credentialSubject.bsn"]}]}}
			]
		}`)
		orgVC := parseVC(t, `{"id": "org-1", "credentialSubject": {"ura": "URA-001"}}`)
		patientVC := parseVC(t, `{"id": "patient-1", "credentialSubject": {"bsn": "BSN-111"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{orgVC, patientVC})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "org-1", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "patient-1", result.Candidates[1].VC.ID.String())
	})

	t.Run("multiple matching candidates picks the first, no error", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		first := parseVC(t, `{"id": "vc-first", "credentialSubject": {"patientId": "123"}}`)
		second := parseVC(t, `{"id": "vc-second", "credentialSubject": {"patientId": "456"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{first, second})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-first", result.Candidates[0].VC.ID.String())
	})

	t.Run("multi-field constraint requires every field to match", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "enrollment",
				"constraints": {"fields": [
					{"id": "patient_id", "path": ["$.credentialSubject.patientId"]},
					{"id": "org_city", "path": ["$.credentialSubject.city"]}
				]}
			}]
		}`)
		// matches only patient_id (missing city) -> not eligible
		partial := parseVC(t, `{"id": "vc-partial", "credentialSubject": {"patientId": "123"}}`)
		// matches both fields -> eligible
		full := parseVC(t, `{"id": "vc-full", "credentialSubject": {"patientId": "123", "city": "Amsterdam"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{partial, full})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-full", result.Candidates[0].VC.ID.String())
	})
}
