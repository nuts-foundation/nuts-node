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

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		assert.ErrorIs(t, err, ErrNoCredentials)
		// Candidates stays populated on error: the unfilled descriptor is present for diagnostics.
		require.Len(t, result.Candidates, 1)
		assert.Equal(t, "patient_credential", result.Candidates[0].InputDescriptor.Id)
		assert.Nil(t, result.Candidates[0].VC)
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

func TestSelect_Eligibility(t *testing.T) {
	t.Run("PD-level format excludes a non-matching proof type", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"format": {"ldp_vc": {"proof_type": ["JsonWebSignature2020"]}},
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		wrongProof := parseVC(t, `{"id": "vc-wrong", "credentialSubject": {"patientId": "123"}, "proof": [{"type": "RsaSignature2018"}]}`)
		rightProof := parseVC(t, `{"id": "vc-right", "credentialSubject": {"patientId": "456"}, "proof": [{"type": "JsonWebSignature2020"}]}`)

		result, err := Select(pd, []vc.VerifiableCredential{wrongProof, rightProof})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-right", result.Candidates[0].VC.ID.String())
	})

	t.Run("descriptor-level format excludes a non-matching proof type", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"format": {"ldp_vc": {"proof_type": ["JsonWebSignature2020"]}},
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		wrongProof := parseVC(t, `{"id": "vc-wrong", "credentialSubject": {"patientId": "123"}, "proof": [{"type": "RsaSignature2018"}]}`)
		rightProof := parseVC(t, `{"id": "vc-right", "credentialSubject": {"patientId": "456"}, "proof": [{"type": "JsonWebSignature2020"}]}`)

		result, err := Select(pd, []vc.VerifiableCredential{wrongProof, rightProof})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-right", result.Candidates[0].VC.ID.String())
	})

	t.Run("descriptor without constraints matches any credential", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{"id": "anything"}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"foo": "bar"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-1", result.Candidates[0].VC.ID.String())
	})
}

func TestSelect_InitialBindings(t *testing.T) {
	t.Run("initial binding selects the credential by field value", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		vc1 := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)
		vc2 := parseVC(t, `{"id": "vc-2", "credentialSubject": {"patientId": "456"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vc1, vc2}, WithInitialBindings(map[string]string{"patient_id": "456"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-2", result.Candidates[0].VC.ID.String())
	})

	t.Run("caller-bound descriptor with multiple matches returns ErrMultipleCredentials", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		vcA := parseVC(t, `{"id": "vc-a", "credentialSubject": {"patientId": "456"}}`)
		vcB := parseVC(t, `{"id": "vc-b", "credentialSubject": {"patientId": "456"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vcA, vcB}, WithInitialBindings(map[string]string{"patient_id": "456"}))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		// Candidates stays populated on error: the undecidable descriptor is present, unfilled.
		require.Len(t, result.Candidates, 1)
		assert.Equal(t, "patient_credential", result.Candidates[0].InputDescriptor.Id)
		assert.Nil(t, result.Candidates[0].VC)
	})

	t.Run("caller-bound descriptor with zero matches returns ErrNoCredentials", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		vc1 := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)
		vc2 := parseVC(t, `{"id": "vc-2", "credentialSubject": {"patientId": "456"}}`)

		_, err := Select(pd, []vc.VerifiableCredential{vc1, vc2}, WithInitialBindings(map[string]string{"patient_id": "nonexistent"}))

		assert.ErrorIs(t, err, ErrNoCredentials)
	})

	t.Run("numeric field value binding", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "room_access",
				"constraints": {"fields": [{"id": "floor", "path": ["$.credentialSubject.floor"]}]}
			}]
		}`)
		// JSON numbers unmarshal to float64; "3" must match float64(3).
		vcA := parseVC(t, `{"id": "vc-a", "credentialSubject": {"floor": 1}}`)
		vcB := parseVC(t, `{"id": "vc-b", "credentialSubject": {"floor": 3}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vcA, vcB}, WithInitialBindings(map[string]string{"floor": "3"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-b", result.Candidates[0].VC.ID.String())
	})

	t.Run("boolean field value binding", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "consent",
				"constraints": {"fields": [{"id": "granted", "path": ["$.credentialSubject.granted"]}]}
			}]
		}`)
		vcTrue := parseVC(t, `{"id": "vc-true", "credentialSubject": {"granted": true}}`)
		vcFalse := parseVC(t, `{"id": "vc-false", "credentialSubject": {"granted": false}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vcTrue, vcFalse}, WithInitialBindings(map[string]string{"granted": "false"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-false", result.Candidates[0].VC.ID.String())
	})

	t.Run("multiple binding keys within a descriptor use AND", func(t *testing.T) {
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
		both := parseVC(t, `{"id": "vc-both", "credentialSubject": {"patientId": "123", "city": "Amsterdam"}}`)
		// matches patient_id but not org_city -> inconsistent
		partial := parseVC(t, `{"id": "vc-partial", "credentialSubject": {"patientId": "123", "city": "Rotterdam"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{partial, both}, WithInitialBindings(map[string]string{"patient_id": "123", "org_city": "Amsterdam"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-both", result.Candidates[0].VC.ID.String())
	})

	t.Run("multiple descriptors with independent binding keys", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "org_credential", "constraints": {"fields": [{"id": "ura", "path": ["$.credentialSubject.ura"]}]}},
				{"id": "patient_enrollment", "constraints": {"fields": [{"id": "bsn", "path": ["$.credentialSubject.bsn"]}]}}
			]
		}`)
		orgA := parseVC(t, `{"id": "org-a", "credentialSubject": {"ura": "URA-001"}}`)
		orgB := parseVC(t, `{"id": "org-b", "credentialSubject": {"ura": "URA-002"}}`)
		patC := parseVC(t, `{"id": "pat-c", "credentialSubject": {"bsn": "BSN-111"}}`)
		patD := parseVC(t, `{"id": "pat-d", "credentialSubject": {"bsn": "BSN-222"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{orgA, orgB, patC, patD},
			WithInitialBindings(map[string]string{"ura": "URA-002", "bsn": "BSN-111"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "org-b", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "pat-c", result.Candidates[1].VC.ID.String())
	})

	t.Run("unknown binding key is silently dropped", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		vc1 := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)
		vc2 := parseVC(t, `{"id": "vc-2", "credentialSubject": {"patientId": "456"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vc1, vc2},
			WithInitialBindings(map[string]string{"patient_id": "456", "nonexistent_field": "whatever"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-2", result.Candidates[0].VC.ID.String())
	})
}

func TestSelect_SubmissionRequirements(t *testing.T) {
	t.Run("all rule with an unfilled group member returns ErrNoCredentials", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "all", "from": "A"}],
			"input_descriptors": [
				{"id": "d1", "group": ["A"], "constraints": {"fields": [{"id": "f1", "path": ["$.credentialSubject.f1"]}]}},
				{"id": "d2", "group": ["A"], "constraints": {"fields": [{"id": "f2", "path": ["$.credentialSubject.f2"]}]}}
			]
		}`)
		// only fills d1; nothing matches d2
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"f1": "x"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		assert.ErrorIs(t, err, ErrNoCredentials)
		// Candidates stays populated on error: it carries the assignment the rule rejected.
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-1", result.Candidates[0].VC.ID.String())
		assert.Nil(t, result.Candidates[1].VC)
	})

	t.Run("all rule with every group member filled keeps all descriptors", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "all", "from": "A"}],
			"input_descriptors": [
				{"id": "d1", "group": ["A"], "constraints": {"fields": [{"id": "f1", "path": ["$.credentialSubject.f1"]}]}},
				{"id": "d2", "group": ["A"], "constraints": {"fields": [{"id": "f2", "path": ["$.credentialSubject.f2"]}]}}
			]
		}`)
		vc1 := parseVC(t, `{"id": "vc-1", "credentialSubject": {"f1": "x"}}`)
		vc2 := parseVC(t, `{"id": "vc-2", "credentialSubject": {"f2": "y"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vc1, vc2})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-1", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "vc-2", result.Candidates[1].VC.ID.String())
	})

	t.Run("pick rule selects a subset and clears the rest", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "pick", "from": "A", "min": 1, "max": 1}],
			"input_descriptors": [
				{"id": "d1", "group": ["A"], "constraints": {"fields": [{"id": "f1", "path": ["$.credentialSubject.f1"]}]}},
				{"id": "d2", "group": ["A"], "constraints": {"fields": [{"id": "f2", "path": ["$.credentialSubject.f2"]}]}}
			]
		}`)
		vc1 := parseVC(t, `{"id": "vc-1", "credentialSubject": {"f1": "x"}}`)
		vc2 := parseVC(t, `{"id": "vc-2", "credentialSubject": {"f2": "y"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{vc1, vc2})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		// pick max 1 keeps the first group member in PD order and clears the rest
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-1", result.Candidates[0].VC.ID.String())
		assert.Nil(t, result.Candidates[1].VC)
	})
}
