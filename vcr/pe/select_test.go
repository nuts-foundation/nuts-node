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
	"fmt"
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

	t.Run("caller-bound matches agreeing on every declared field are interchangeable", func(t *testing.T) {
		// The matches are identical on all declared field ids (a reissued duplicate); no
		// credential_selection key could separate them, so the engine picks the first.
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

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "vc-a", result.Candidates[0].VC.ID.String())
	})

	t.Run("caller-bound matches differing on another declared field return ErrMultipleCredentials", func(t *testing.T) {
		// The consent scenario with consent_status declared: the caller pins the patient, but
		// the survivors contradict each other on a declared id. Erroring is actionable: bind
		// consent_status.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "consent_credential",
				"constraints": {"fields": [
					{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]},
					{"id": "consent_status", "path": ["$.credentialSubject.consentStatus"]}
				]}
			}]
		}`)
		granted := parseVC(t, `{"id": "consent-granted", "credentialSubject": {"bsn": "999911234", "consentStatus": true}}`)
		withdrawn := parseVC(t, `{"id": "consent-withdrawn", "credentialSubject": {"bsn": "999911234", "consentStatus": false}}`)

		result, err := Select(pd, []vc.VerifiableCredential{granted, withdrawn},
			WithInitialBindings(map[string]string{"patient_bsn": "999911234"}))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		require.Len(t, result.Candidates, 1)
		assert.Nil(t, result.Candidates[0].VC)
	})

	t.Run("caller-bound matches differing only in undeclared fields are interchangeable", func(t *testing.T) {
		// The same consent scenario without consent_status in the PD: the PD is the data
		// contract (undeclared fields are not introspectable), so the difference plays no role
		// and the engine picks the first. The divergence is surfaced in the MatchReport.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "consent_credential",
				"constraints": {"fields": [{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]}]}
			}]
		}`)
		granted := parseVC(t, `{"id": "consent-granted", "credentialSubject": {"bsn": "999911234", "consentStatus": true}}`)
		withdrawn := parseVC(t, `{"id": "consent-withdrawn", "credentialSubject": {"bsn": "999911234", "consentStatus": false}}`)

		result, err := Select(pd, []vc.VerifiableCredential{granted, withdrawn},
			WithInitialBindings(map[string]string{"patient_bsn": "999911234"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "consent-granted", result.Candidates[0].VC.ID.String())
	})

	t.Run("candidates stay full length when a later descriptor errors", func(t *testing.T) {
		// The failing descriptor comes first (bound matches contradict on the declared status
		// field); the descriptor after it must still appear in Result.Candidates (one entry per
		// descriptor, PD order, on every path).
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "patient_credential", "constraints": {"fields": [
					{"id": "patient_id", "path": ["$.credentialSubject.patientId"]},
					{"id": "status", "path": ["$.credentialSubject.status"]}
				]}},
				{"id": "org_credential", "constraints": {"fields": [{"id": "ura", "path": ["$.credentialSubject.ura"]}]}}
			]
		}`)
		patA := parseVC(t, `{"id": "pat-a", "credentialSubject": {"patientId": "456", "status": "active"}}`)
		patB := parseVC(t, `{"id": "pat-b", "credentialSubject": {"patientId": "456", "status": "inactive"}}`)
		org := parseVC(t, `{"id": "org-1", "credentialSubject": {"ura": "URA-001"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{patA, patB, org},
			WithInitialBindings(map[string]string{"patient_id": "456"}))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		require.Len(t, result.Candidates, 2)
		assert.Equal(t, "patient_credential", result.Candidates[0].InputDescriptor.Id)
		assert.Nil(t, result.Candidates[0].VC)
		// best-effort: the unaffected descriptor is still reported with its match
		assert.Equal(t, "org_credential", result.Candidates[1].InputDescriptor.Id)
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "org-1", result.Candidates[1].VC.ID.String())
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

	t.Run("unresolved optional field does not bind between descriptors", func(t *testing.T) {
		// Unresolved-optional rule: descriptor A's optional foo does not resolve on its candidate, so it must
		// not manufacture a binding that conflicts with descriptor B's resolved foo=Z.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "A", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"], "optional": true}
				]}},
				{"id": "B", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}}
			]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"bar": "unrelated"}}`)
		b1 := parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "Z"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{a1, b1})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a1", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "b1", result.Candidates[1].VC.ID.String())
	})

	t.Run("caller-bound field must resolve: all candidates unresolved is ErrNoCredentials", func(t *testing.T) {
		// Initial bindings are strict (legacy field-selector semantics): a caller who pins foo
		// never receives a credential without a resolvable foo. Two such candidates must not
		// drift into ErrMultipleCredentials via the unresolved-is-consistent leniency.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "A",
				"constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"], "optional": true}
				]}
			}]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"bar": "x"}}`)
		a2 := parseVC(t, `{"id": "a2", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"bar": "y"}}`)

		_, err := Select(pd, []vc.VerifiableCredential{a1, a2}, WithInitialBindings(map[string]string{"foo": "Z"}))

		assert.ErrorIs(t, err, ErrNoCredentials)
	})

	t.Run("caller-bound field must resolve: the resolving candidate wins over unresolved ones", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "A",
				"constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"], "optional": true}
				]}
			}]
		}`)
		unresolved := parseVC(t, `{"id": "a-unresolved", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"bar": "x"}}`)
		resolving := parseVC(t, `{"id": "a-resolving", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "Z"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{unresolved, resolving}, WithInitialBindings(map[string]string{"foo": "Z"}))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 1)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a-resolving", result.Candidates[0].VC.ID.String())
	})

	t.Run("caller-bound multiplicity errors even on an optional descriptor", func(t *testing.T) {
		// Optionality governs zero-vs-some, not one-vs-many: skipping an optional descriptor
		// because the caller's explicit selection turned out ambiguous would silently discard
		// an instruction. The error names the descriptor; the remedy is a second key (status).
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [
				{"rule": "all", "from": "GA"},
				{"rule": "pick", "from": "GB", "min": 0, "max": 1}
			],
			"input_descriptors": [
				{"id": "A", "group": ["GA"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "a_id", "path": ["$.credentialSubject.aId"]}
				]}},
				{"id": "B", "group": ["GB"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]},
					{"id": "status", "path": ["$.credentialSubject.status"]}
				]}}
			]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"aId": "a"}}`)
		b1 := parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"bsn": "999911234", "status": "active"}}`)
		b2 := parseVC(t, `{"id": "b2", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"bsn": "999911234", "status": "inactive"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{a1, b1, b2},
			WithInitialBindings(map[string]string{"patient_bsn": "999911234"}))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		assert.ErrorContains(t, err, "B")
		// full-length candidates: the pinned-but-ambiguous descriptor is unfilled, A is best-effort
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Nil(t, result.Candidates[1].VC)
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

func TestSelect_SameIDBinding(t *testing.T) {
	t.Run("same id across descriptors must agree, backtracking into a consistent pair", func(t *testing.T) {
		// Same-id agreement worked example (design #4253): HCP-A (ura=1) is tried first, conflicts with the only
		// delegation (ura=2), so the search backtracks and lands on (HCP-B, Delegation-X).
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "id_healthcare_provider", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "HCPCredential"}},
					{"id": "org_ura", "path": ["$.credentialSubject.ura"]}
				]}},
				{"id": "id_professional_delegation", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "DelegationCredential"}},
					{"id": "org_ura", "path": ["$.credentialSubject.ura"]}
				]}}
			]
		}`)
		hcpA := parseVC(t, `{"id": "hcp-a", "type": ["VerifiableCredential", "HCPCredential"], "credentialSubject": {"ura": "1"}}`)
		hcpB := parseVC(t, `{"id": "hcp-b", "type": ["VerifiableCredential", "HCPCredential"], "credentialSubject": {"ura": "2"}}`)
		delegationX := parseVC(t, `{"id": "delegation-x", "type": ["VerifiableCredential", "DelegationCredential"], "credentialSubject": {"ura": "2"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{hcpA, hcpB, delegationX})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "hcp-b", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "delegation-x", result.Candidates[1].VC.ID.String())
	})

	t.Run("optional descriptor is skipped only after exhausting alternatives elsewhere", func(t *testing.T) {
		// Prefer-fill-over-skip worked example (design #4253): A1's binding admits B1 but kills C1; A2's binding kills B1
		// but admits C1. Skipping optional B under A1 does not save C, so the search must
		// revise A. Expected: A=A2, B=nil, C=C1.
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [
				{"rule": "all", "from": "GA"},
				{"rule": "pick", "from": "GB", "min": 0, "max": 1},
				{"rule": "all", "from": "GC"}
			],
			"input_descriptors": [
				{"id": "A", "group": ["GA"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}},
				{"id": "B", "group": ["GB"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}},
				{"id": "C", "group": ["GC"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "CCredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}}
			]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "1"}}`)
		a2 := parseVC(t, `{"id": "a2", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "2"}}`)
		b1 := parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "1"}}`)
		c1 := parseVC(t, `{"id": "c1", "type": ["VerifiableCredential", "CCredential"], "credentialSubject": {"foo": "2"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{a1, a2, b1, c1})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 3)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a2", result.Candidates[0].VC.ID.String())
		assert.Nil(t, result.Candidates[1].VC)
		require.NotNil(t, result.Candidates[2].VC)
		assert.Equal(t, "c1", result.Candidates[2].VC.ID.String())
	})

	t.Run("either-or pick-1 sharing an id fills one descriptor and skips the other", func(t *testing.T) {
		// Both descriptors carry doctor_id but resolve different values; a pick-1 group is
		// satisfied by the first in PD order, without a binding conflict or ambiguity error.
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "pick", "from": "doctor", "count": 1}],
			"input_descriptors": [
				{"id": "enrollment", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "EnrollmentCredential"}},
					{"id": "doctor_id", "path": ["$.credentialSubject.doctorId"]}
				]}},
				{"id": "consent", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ConsentCredential"}},
					{"id": "doctor_id", "path": ["$.credentialSubject.doctorId"]}
				]}}
			]
		}`)
		enrollment := parseVC(t, `{"id": "enrollment-1", "type": ["VerifiableCredential", "EnrollmentCredential"], "credentialSubject": {"doctorId": "A"}}`)
		consent := parseVC(t, `{"id": "consent-1", "type": ["VerifiableCredential", "ConsentCredential"], "credentialSubject": {"doctorId": "B"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{enrollment, consent})

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "enrollment-1", result.Candidates[0].VC.ID.String())
		assert.Nil(t, result.Candidates[1].VC)
	})
}

func TestSelect_Bindings(t *testing.T) {
	t.Run("bindings expose the resolved id-values of the chosen assignment", func(t *testing.T) {
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
		assert.Equal(t, map[string]string{"ura": "URA-001", "bsn": "BSN-111"}, result.Bindings)
	})

	t.Run("a descriptor cleared by a rule contributes no bindings", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "pick", "from": "doctor", "count": 1}],
			"input_descriptors": [
				{"id": "enrollment", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "EnrollmentCredential"}},
					{"id": "doctor_id", "path": ["$.credentialSubject.doctorId"]}
				]}},
				{"id": "consent", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ConsentCredential"}},
					{"id": "consent_id", "path": ["$.credentialSubject.consentId"]}
				]}}
			]
		}`)
		enrollment := parseVC(t, `{"id": "enrollment-1", "type": ["VerifiableCredential", "EnrollmentCredential"], "credentialSubject": {"doctorId": "A"}}`)
		consent := parseVC(t, `{"id": "consent-1", "type": ["VerifiableCredential", "ConsentCredential"], "credentialSubject": {"consentId": "C"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{enrollment, consent})

		require.NoError(t, err)
		// pick-1 keeps enrollment and clears consent; only the surviving credential binds
		assert.Equal(t, map[string]string{"doctor_id": "A"}, result.Bindings)
	})

	t.Run("unknown initial binding keys are not echoed", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred},
			WithInitialBindings(map[string]string{"patient_id": "123", "sp_only_key": "whatever"}))

		require.NoError(t, err)
		assert.Equal(t, map[string]string{"patient_id": "123"}, result.Bindings)
	})

	t.Run("no bindings on error", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"], "filter": {"type": "string", "const": "999"}}]}
			}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		assert.ErrorIs(t, err, ErrNoCredentials)
		assert.Nil(t, result.Bindings)
	})

	t.Run("two-VP composition chains bindings through a field-id filter", func(t *testing.T) {
		// Cross-VP capture as straight Go at the call site: build the org VP, filter its bindings down
		// to the SP PD's field ids, seed the SP build with the survivors.
		orgPD := parsePD(t, `{
			"id": "org-pd",
			"input_descriptors": [
				{"id": "org", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.orgDid"]}]}},
				{"id": "patient", "constraints": {"fields": [{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]}]}}
			]
		}`)
		spPD := parsePD(t, `{
			"id": "sp-pd",
			"input_descriptors": [
				{"id": "delegation", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.issuedTo"]}]}}
			]
		}`)
		orgVC := parseVC(t, `{"id": "org-1", "credentialSubject": {"orgDid": "did:web:org"}}`)
		patientVC := parseVC(t, `{"id": "patient-1", "credentialSubject": {"bsn": "999911234"}}`)
		delegationRight := parseVC(t, `{"id": "delegation-right", "credentialSubject": {"issuedTo": "did:web:org"}}`)
		delegationWrong := parseVC(t, `{"id": "delegation-wrong", "credentialSubject": {"issuedTo": "did:web:other"}}`)

		orgResult, err := Select(orgPD, []vc.VerifiableCredential{orgVC, patientVC})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"org_did": "did:web:org", "patient_bsn": "999911234"}, orgResult.Bindings)

		// caller-side filter: keep only keys that are field ids on the SP PD
		spFieldIDs := map[string]bool{"org_did": true}
		seed := make(map[string]string)
		for key, value := range orgResult.Bindings {
			if spFieldIDs[key] {
				seed[key] = value
			}
		}

		spResult, err := Select(spPD, []vc.VerifiableCredential{delegationWrong, delegationRight}, WithInitialBindings(seed))
		require.NoError(t, err)
		require.NotNil(t, spResult.Candidates[0].VC)
		assert.Equal(t, "delegation-right", spResult.Candidates[0].VC.ID.String())
	})
}

func TestSelect_Strategy(t *testing.T) {
	// Ambiguity worked example (design #4253): two genuinely different ways to satisfy the PD.
	ambiguousPD := `{
		"id": "test-pd",
		"input_descriptors": [
			{"id": "A", "constraints": {"fields": [
				{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
				{"id": "foo", "path": ["$.credentialSubject.foo"]}
			]}},
			{"id": "B", "constraints": {"fields": [
				{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
				{"id": "foo", "path": ["$.credentialSubject.foo"]}
			]}}
		]
	}`
	a1 := `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "X"}}`
	a2 := `{"id": "a2", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "Y"}}`
	b1 := `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "X"}}`
	b2 := `{"id": "b2", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "Y"}}`

	t.Run("Strict reports a rival assignment naming the ambiguous descriptors", func(t *testing.T) {
		pd := parsePD(t, ambiguousPD)
		creds := []vc.VerifiableCredential{parseVC(t, a1), parseVC(t, a2), parseVC(t, b1), parseVC(t, b2)}

		result, err := Select(pd, creds, WithStrategy(Strict))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		assert.ErrorContains(t, err, "A")
		assert.ErrorContains(t, err, "B")
		// the decisive (first) assignment is still reported for diagnostics
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a1", result.Candidates[0].VC.ID.String())
	})

	t.Run("FirstMatch returns the first assignment for the same PD", func(t *testing.T) {
		pd := parsePD(t, ambiguousPD)
		creds := []vc.VerifiableCredential{parseVC(t, a1), parseVC(t, a2), parseVC(t, b1), parseVC(t, b2)}

		result, err := Select(pd, creds)

		require.NoError(t, err)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a1", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "b1", result.Candidates[1].VC.ID.String())
	})

	t.Run("Strict with a disambiguating initial binding succeeds", func(t *testing.T) {
		pd := parsePD(t, ambiguousPD)
		creds := []vc.VerifiableCredential{parseVC(t, a1), parseVC(t, a2), parseVC(t, b1), parseVC(t, b2)}

		result, err := Select(pd, creds, WithStrategy(Strict), WithInitialBindings(map[string]string{"foo": "X"}))

		require.NoError(t, err)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a1", result.Candidates[0].VC.ID.String())
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "b1", result.Candidates[1].VC.ID.String())
	})

	t.Run("Strict does not flag interchangeable credentials", func(t *testing.T) {
		// A reissued duplicate: identical id-bearing values, one binding tuple, one rival.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "A",
				"constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}
			}]
		}`)
		first := parseVC(t, `{"id": "a-first", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "X"}}`)
		duplicate := parseVC(t, `{"id": "a-duplicate", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "X"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{first, duplicate}, WithStrategy(Strict))

		require.NoError(t, err)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "a-first", result.Candidates[0].VC.ID.String())
	})

	t.Run("Strict flags a rival on an optional descriptor", func(t *testing.T) {
		// Optionality does not exempt a descriptor from ambiguity: two materially different
		// credentials can fill it, so the selection is ambiguous even though skipping it would
		// also have been acceptable.
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [
				{"rule": "all", "from": "GA"},
				{"rule": "pick", "from": "GB", "min": 0, "max": 1}
			],
			"input_descriptors": [
				{"id": "A", "group": ["GA"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "a_id", "path": ["$.credentialSubject.aId"]}
				]}},
				{"id": "B", "group": ["GB"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "status", "path": ["$.credentialSubject.status"]}
				]}}
			]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"aId": "a"}}`)
		b1 := parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"status": "active"}}`)
		b2 := parseVC(t, `{"id": "b2", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"status": "inactive"}}`)

		_, err := Select(pd, []vc.VerifiableCredential{a1, b1, b2}, WithStrategy(Strict))

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		assert.ErrorContains(t, err, "B")
	})

	t.Run("Strict stays silent on fill-versus-skip for an optional descriptor", func(t *testing.T) {
		// With a single candidate for the optional descriptor, the skip branch also produces a
		// complete assignment, but fill is deterministically preferred and never rivals skip.
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [
				{"rule": "all", "from": "GA"},
				{"rule": "pick", "from": "GB", "min": 0, "max": 1}
			],
			"input_descriptors": [
				{"id": "A", "group": ["GA"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "a_id", "path": ["$.credentialSubject.aId"]}
				]}},
				{"id": "B", "group": ["GB"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "status", "path": ["$.credentialSubject.status"]}
				]}}
			]
		}`)
		a1 := parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"aId": "a"}}`)
		b1 := parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"status": "active"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{a1, b1}, WithStrategy(Strict))

		require.NoError(t, err)
		require.Len(t, result.Candidates, 2)
		require.NotNil(t, result.Candidates[1].VC)
		assert.Equal(t, "b1", result.Candidates[1].VC.ID.String())
	})

	t.Run("Strict does not flag an either-or pick-1 group", func(t *testing.T) {
		// The alternatives live in different descriptors of a pick-1 group; no descriptor is
		// filled by both assignments, so there is no rival.
		pd := parsePD(t, `{
			"id": "test-pd",
			"submission_requirements": [{"rule": "pick", "from": "doctor", "count": 1}],
			"input_descriptors": [
				{"id": "enrollment", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "EnrollmentCredential"}},
					{"id": "doctor_id", "path": ["$.credentialSubject.doctorId"]}
				]}},
				{"id": "consent", "group": ["doctor"], "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ConsentCredential"}},
					{"id": "doctor_id", "path": ["$.credentialSubject.doctorId"]}
				]}}
			]
		}`)
		enrollment := parseVC(t, `{"id": "enrollment-1", "type": ["VerifiableCredential", "EnrollmentCredential"], "credentialSubject": {"doctorId": "A"}}`)
		consent := parseVC(t, `{"id": "consent-1", "type": ["VerifiableCredential", "ConsentCredential"], "credentialSubject": {"doctorId": "B"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{enrollment, consent}, WithStrategy(Strict))

		require.NoError(t, err)
		require.NotNil(t, result.Candidates[0].VC)
		assert.Equal(t, "enrollment-1", result.Candidates[0].VC.ID.String())
		assert.Nil(t, result.Candidates[1].VC)
	})
}

func TestSelect_Trace(t *testing.T) {
	filterPD := `{
		"id": "test-pd",
		"input_descriptors": [{
			"id": "patient_credential",
			"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"], "filter": {"type": "string", "const": "999"}}]}
		}]
	}`

	t.Run("trace off leaves Report nil", func(t *testing.T) {
		pd := parsePD(t, filterPD)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "999"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{cred})

		require.NoError(t, err)
		assert.Nil(t, result.Report)
	})

	t.Run("filter dismissal and selection are reported", func(t *testing.T) {
		pd := parsePD(t, filterPD)
		wrong := parseVC(t, `{"id": "vc-wrong", "credentialSubject": {"patientId": "123"}}`)
		right := parseVC(t, `{"id": "vc-right", "credentialSubject": {"patientId": "999"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{wrong, right}, WithSelectionTrace())

		require.NoError(t, err)
		require.NotNil(t, result.Report)
		assert.Equal(t, OutcomeMatched, result.Report.Outcome)
		require.Len(t, result.Report.Descriptors, 1)
		descriptor := result.Report.Descriptors[0]
		assert.Equal(t, "patient_credential", descriptor.DescriptorID)
		assert.Equal(t, "vc-right", descriptor.SelectedID)
		assert.False(t, descriptor.Skipped)
		require.Len(t, descriptor.Considered, 2)
		dismissed := descriptor.Considered[0]
		assert.Equal(t, "vc-wrong", dismissed.CredentialID)
		assert.False(t, dismissed.Eligible)
		require.NotNil(t, dismissed.Dismissal)
		assert.Equal(t, ReasonFilter, dismissed.Dismissal.Reason)
		selected := descriptor.Considered[1]
		assert.True(t, selected.Eligible)
		assert.Nil(t, selected.Dismissal)
	})

	t.Run("missing value is reported as constraint_no_value", func(t *testing.T) {
		pd := parsePD(t, filterPD)
		unrelated := parseVC(t, `{"id": "vc-unrelated", "credentialSubject": {"somethingElse": "x"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{unrelated}, WithSelectionTrace())

		assert.ErrorIs(t, err, ErrNoCredentials)
		require.NotNil(t, result.Report)
		assert.Equal(t, OutcomeNoCredentials, result.Report.Outcome)
		dismissed := result.Report.Descriptors[0].Considered[0]
		require.NotNil(t, dismissed.Dismissal)
		assert.Equal(t, ReasonNoValue, dismissed.Dismissal.Reason)
	})

	t.Run("format mismatch is reported", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"format": {"ldp_vc": {"proof_type": ["JsonWebSignature2020"]}},
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		wrongProof := parseVC(t, `{"id": "vc-wrong", "credentialSubject": {"patientId": "123"}, "proof": [{"type": "RsaSignature2018"}]}`)

		result, err := Select(pd, []vc.VerifiableCredential{wrongProof}, WithSelectionTrace())

		assert.ErrorIs(t, err, ErrNoCredentials)
		require.NotNil(t, result.Report)
		dismissed := result.Report.Descriptors[0].Considered[0]
		require.NotNil(t, dismissed.Dismissal)
		assert.Equal(t, ReasonFormat, dismissed.Dismissal.Reason)
	})

	t.Run("binding conflict on the decisive path is reported", func(t *testing.T) {
		// Same-id agreement example under trace: HCP-A is eligible but disagrees with the decisive
		// assignment's org_ura=2.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "id_healthcare_provider", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "HCPCredential"}},
					{"id": "org_ura", "path": ["$.credentialSubject.ura"]}
				]}},
				{"id": "id_professional_delegation", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "DelegationCredential"}},
					{"id": "org_ura", "path": ["$.credentialSubject.ura"]}
				]}}
			]
		}`)
		hcpA := parseVC(t, `{"id": "hcp-a", "type": ["VerifiableCredential", "HCPCredential"], "credentialSubject": {"ura": "1"}}`)
		hcpB := parseVC(t, `{"id": "hcp-b", "type": ["VerifiableCredential", "HCPCredential"], "credentialSubject": {"ura": "2"}}`)
		delegationX := parseVC(t, `{"id": "delegation-x", "type": ["VerifiableCredential", "DelegationCredential"], "credentialSubject": {"ura": "2"}}`)

		result, err := Select(pd, []vc.VerifiableCredential{hcpA, hcpB, delegationX}, WithSelectionTrace())

		require.NoError(t, err)
		require.NotNil(t, result.Report)
		assert.Equal(t, OutcomeMatched, result.Report.Outcome)
		hcpReport := result.Report.Descriptors[0]
		assert.Equal(t, "hcp-b", hcpReport.SelectedID)
		require.Len(t, hcpReport.Considered, 3)
		dismissed := hcpReport.Considered[0]
		assert.Equal(t, "hcp-a", dismissed.CredentialID)
		assert.True(t, dismissed.Eligible)
		require.NotNil(t, dismissed.Dismissal)
		assert.Equal(t, ReasonBindingConflict, dismissed.Dismissal.Reason)
		assert.Equal(t, "org_ura", dismissed.Dismissal.FieldID)
		assert.Equal(t, "2", dismissed.Dismissal.Expected)
		assert.Equal(t, "1", dismissed.Dismissal.Found)
	})

	t.Run("diverging interchangeable alternatives are flagged", func(t *testing.T) {
		// Two consents for the same bsn differ in an undeclared field: interchangeable by
		// contract, but the report flags the divergence for the operator.
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "consent_credential",
				"constraints": {"fields": [{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]}]}
			}]
		}`)
		granted := parseVC(t, `{"id": "consent-granted", "credentialSubject": {"bsn": "999911234", "consentStatus": true}}`)
		withdrawn := parseVC(t, `{"id": "consent-withdrawn", "credentialSubject": {"bsn": "999911234", "consentStatus": false}}`)

		result, err := Select(pd, []vc.VerifiableCredential{granted, withdrawn}, WithSelectionTrace())

		require.NoError(t, err)
		require.NotNil(t, result.Report)
		assert.True(t, result.Report.Descriptors[0].DivergingAlternatives)
	})

	t.Run("true duplicates are not flagged as diverging", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "consent_credential",
				"constraints": {"fields": [{"id": "patient_bsn", "path": ["$.credentialSubject.bsn"]}]}
			}]
		}`)
		original := parseVC(t, `{"id": "consent-1", "credentialSubject": {"bsn": "999911234", "consentStatus": true}}`)
		reissued := parseVC(t, `{"id": "consent-2", "credentialSubject": {"bsn": "999911234", "consentStatus": true}, "proof": [{"type": "JsonWebSignature2020"}]}`)

		result, err := Select(pd, []vc.VerifiableCredential{original, reissued}, WithSelectionTrace())

		require.NoError(t, err)
		require.NotNil(t, result.Report)
		assert.False(t, result.Report.Descriptors[0].DivergingAlternatives)
	})

	t.Run("ambiguity is reported with the ambiguous descriptors", func(t *testing.T) {
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [
				{"id": "A", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}},
				{"id": "B", "constraints": {"fields": [
					{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
					{"id": "foo", "path": ["$.credentialSubject.foo"]}
				]}}
			]
		}`)
		creds := []vc.VerifiableCredential{
			parseVC(t, `{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "X"}}`),
			parseVC(t, `{"id": "a2", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "Y"}}`),
			parseVC(t, `{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "X"}}`),
			parseVC(t, `{"id": "b2", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "Y"}}`),
		}

		result, err := Select(pd, creds, WithStrategy(Strict), WithSelectionTrace())

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		require.NotNil(t, result.Report)
		assert.Equal(t, OutcomeMultipleCredentials, result.Report.Outcome)
		assert.Equal(t, []string{"A", "B"}, result.Report.AmbiguousDescriptors)
	})
}

func TestSelect_NodeLimit(t *testing.T) {
	// A PD engineered to explode: descriptors with independent ids multiply combinations, and a
	// final unfillable descriptor forces the search to visit all of them before concluding
	// failure. PDs are counterparty-supplied in wallet flows, so the search must abort instead
	// of burning CPU.
	t.Run("a pathological search aborts with a limit error", func(t *testing.T) {
		originalLimit := searchNodeLimit
		searchNodeLimit = 100
		defer func() { searchNodeLimit = originalLimit }()

		descriptors := ""
		var creds []vc.VerifiableCredential
		for d := 0; d < 6; d++ {
			descriptors += fmt.Sprintf(`{"id": "d%d", "constraints": {"fields": [
				{"path": ["$.type"], "filter": {"type": "string", "const": "Type%d"}},
				{"id": "id%d", "path": ["$.credentialSubject.value"]}
			]}},`, d, d, d)
			for c := 0; c < 3; c++ {
				creds = append(creds, parseVC(t, fmt.Sprintf(
					`{"id": "vc-%d-%d", "type": ["VerifiableCredential", "Type%d"], "credentialSubject": {"value": "v%d"}}`, d, c, d, c)))
			}
		}
		pd := parsePD(t, `{
			"id": "exploding-pd",
			"input_descriptors": [`+descriptors+`
				{"id": "impossible", "constraints": {"fields": [
					{"path": ["$.credentialSubject.nonexistent"], "filter": {"type": "string", "const": "never"}}
				]}}
			]
		}`)

		_, err := Select(pd, creds)

		require.Error(t, err)
		assert.ErrorContains(t, err, "exploding-pd")
		assert.ErrorContains(t, err, "limit")
	})

	t.Run("a realistic search stays far below the default limit", func(t *testing.T) {
		// sanity check: an ordinary single-descriptor match never comes close to the cap
		pd := parsePD(t, `{
			"id": "test-pd",
			"input_descriptors": [{
				"id": "patient_credential",
				"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
			}]
		}`)
		cred := parseVC(t, `{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`)

		_, err := Select(pd, []vc.VerifiableCredential{cred})

		require.NoError(t, err)
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
