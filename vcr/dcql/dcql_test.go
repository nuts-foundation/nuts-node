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

package dcql

import (
	"encoding/json"
	"fmt"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	t.Run("single claim with matching value returns credential", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123456789"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{
					Path:   []any{"credentialSubject", "patientId"},
					Values: []any{"123456789"},
				},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, credential, result[0])
	})
	t.Run("single claim with non-matching value returns empty", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123456789"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{
					Path:   []any{"credentialSubject", "patientId"},
					Values: []any{"999999999"},
				},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("nested path resolves correctly", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"hasEnrollment": map[string]any{
						"patient": map[string]any{
							"identifier": map[string]any{
								"value": "123456789",
							},
						},
					},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{
					Path:   []any{"credentialSubject", "hasEnrollment", "patient", "identifier", "value"},
					Values: []any{"123456789"},
				},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("multiple values use OR semantics", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"postalCode": "90210"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{
					Path:   []any{"credentialSubject", "postalCode"},
					Values: []any{"90210", "90211"},
				},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("multiple values none matching returns empty", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"postalCode": "12345"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{
					Path:   []any{"credentialSubject", "postalCode"},
					Values: []any{"90210", "90211"},
				},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("multiple claims use AND semantics — all match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"patientId": "123",
					"type":      "pharmacy",
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
				{Path: []any{"credentialSubject", "type"}, Values: []any{"pharmacy"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("multiple claims use AND semantics — one fails", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"patientId": "123",
					"type":      "hospital",
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
				{Path: []any{"credentialSubject", "type"}, Values: []any{"pharmacy"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("missing field in credential does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"otherField": "value"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("empty credentialSubject does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("empty credentials list returns empty", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "test",
			Claims: []ClaimsQuery{{Path: []any{"credentialSubject", "id"}, Values: []any{"x"}}},
		}

		result, err := Match(query, []vc.VerifiableCredential{})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("multiple credentials returns only matching ones", func(t *testing.T) {
		match := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{{"patientId": "123"}},
		}
		noMatch := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{{"patientId": "456"}},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{noMatch, match, noMatch})

		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, match, result[0])
	})
	t.Run("integer value matching", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"age": float64(42)},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "age"}, Values: []any{float64(42)}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("boolean value matching", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"active": true},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "active"}, Values: []any{true}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("boolean value mismatch", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"active": false},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "active"}, Values: []any{true}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("claim without values matches if field exists", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "anything"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("claim without values does not match if field missing", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"otherField": "value"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	// This test verifies that matching works correctly when both the query and credential
	// are deserialized from JSON, as they would be in production. JSON unmarshalling can
	// produce different Go types than hand-constructed structs (e.g., nested maps vs typed
	// fields), so this catches type mismatches that unit tests with Go literals would miss.
	t.Run("JSON-deserialized query matches JSON-deserialized credential", func(t *testing.T) {
		var credential vc.VerifiableCredential
		err := credential.UnmarshalJSON([]byte(`{
			"type": ["VerifiableCredential", "PatientEnrollmentCredential"],
			"credentialSubject": [{
				"hasEnrollment": {
					"patient": {
						"identifier": {
							"system": "http://fhir.nl/fhir/NamingSystem/bsn",
							"value": "123456789"
						}
					}
				}
			}]
		}`))
		require.NoError(t, err)

		var query CredentialQuery
		err = json.Unmarshal([]byte(`{
			"id": "id_patient_enrollment",
			"claims": [
				{
					"path": ["credentialSubject", "hasEnrollment", "patient", "identifier", "value"],
					"values": ["123456789"]
				}
			]
		}`), &query)
		require.NoError(t, err)

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("path with integer element resolves array index", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"roleCodes": []any{"01.015", "30.000", "17.000"},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Select the second role code (30.000 = Verpleegkundige)
				{Path: []any{"credentialSubject", "roleCodes", 1}, Values: []any{"30.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("path with integer element does not match wrong index", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"roleCodes": []any{"01.015", "30.000", "17.000"},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Index 1 is "30.000" (Verpleegkundige), not "17.000" (Apotheker)
				{Path: []any{"credentialSubject", "roleCodes", 1}, Values: []any{"17.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("null wildcard matches value anywhere in array", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"roleCodes": []any{"01.015", "30.000", "17.000"},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// null wildcard selects all elements — match if "30.000" (Verpleegkundige) is anywhere in the array
				{Path: []any{"credentialSubject", "roleCodes", nil}, Values: []any{"30.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("null wildcard does not match when value absent from array", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"roleCodes": []any{"01.015", "30.000", "17.000"},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// "89.000" (Dietist) is not in the array
				{Path: []any{"credentialSubject", "roleCodes", nil}, Values: []any{"89.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("null wildcard in middle of path matches nested field in array elements", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"qualifications": []any{
						map[string]any{"roleCode": "01.015", "name": "Huisarts"},
						map[string]any{"roleCode": "30.000", "name": "Verpleegkundige"},
						map[string]any{"roleCode": "17.000", "name": "Apotheker"},
					},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Wildcard selects all qualifications, then match on nested roleCode
				{Path: []any{"credentialSubject", "qualifications", nil, "roleCode"}, Values: []any{"30.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("null wildcard in middle of path does not match when nested field absent", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"qualifications": []any{
						map[string]any{"roleCode": "01.015", "name": "Huisarts"},
						map[string]any{"roleCode": "30.000", "name": "Verpleegkundige"},
					},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// "89.000" (Dietist) is not in any qualification's roleCode
				{Path: []any{"credentialSubject", "qualifications", nil, "roleCode"}, Values: []any{"89.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("nested wildcards match values in arrays of arrays", func(t *testing.T) {
		// A credential with departments, each containing multiple employees with role codes
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"departments": []any{
						map[string]any{
							"employees": []any{
								map[string]any{"roleCode": "01.015"},
								map[string]any{"roleCode": "30.000"},
							},
						},
						map[string]any{
							"employees": []any{
								map[string]any{"roleCode": "17.000"},
								map[string]any{"roleCode": "04.000"},
							},
						},
					},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Two wildcards: all departments → all employees → roleCode
				// Should find "17.000" (Apotheker) in the second department
				{Path: []any{"credentialSubject", "departments", nil, "employees", nil, "roleCode"}, Values: []any{"17.000"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("path resolves root-level fields", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			Issuer: ssi.MustParseURI("did:x509:0:sha256:abc123"),
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"issuer"}, Values: []any{"did:x509:0:sha256:abc123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("invalid credential query ID returns error", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "invalid id!",
			Claims: []ClaimsQuery{},
		}

		_, err := Match(query, []vc.VerifiableCredential{})

		assert.ErrorContains(t, err, "invalid credential query id")
	})
	t.Run("empty credential query ID returns error", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "",
			Claims: []ClaimsQuery{},
		}

		_, err := Match(query, []vc.VerifiableCredential{})

		assert.ErrorContains(t, err, "invalid credential query id")
	})
	t.Run("float path element that is not an integer returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"roles": []any{"01.015", "30.000"}},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "roles", float64(1.5)}, Values: []any{"30.000"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "invalid path element")
	})
	t.Run("boolean path element returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"field": "value"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", true}, Values: []any{"value"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "invalid path element type")
	})
	t.Run("single credentialSubject with explicit index 0 works", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", 0, "patientId"}, Values: []any{"123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("multiple credentialSubjects without index returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123"},
				{"patientId": "456"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "patientId"}, Values: []any{"123"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "index")
	})
	t.Run("multiple credentialSubjects with index works", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123"},
				{"patientId": "456"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", 1, "patientId"}, Values: []any{"456"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
	t.Run("negative int path element returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"roles": []any{"01.015", "30.000"}},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "roles", -1}, Values: []any{"30.000"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "invalid path element")
	})
	t.Run("float64 exceeding MaxInt returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"roles": []any{"01.015"}},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "roles", float64(1e19)}, Values: []any{"01.015"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "invalid path element")
	})
	t.Run("empty path in claims query returns error", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"field": "value"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{}, Values: []any{"value"}},
			},
		}

		_, err := Match(query, []vc.VerifiableCredential{credential})

		assert.ErrorContains(t, err, "path must be a non-empty array")
	})
	t.Run("path ending at object does not panic on value comparison", func(t *testing.T) {
		// When the path resolves to a map (non-comparable type), containsExpectedValue
		// must not panic on == comparison. It should simply not match.
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{
					"hasEnrollment": map[string]any{
						"patient": map[string]any{
							"name": "John",
						},
					},
				},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Path stops at the object level, resolved value is a map
				{Path: []any{"credentialSubject", "hasEnrollment", "patient"}, Values: []any{"John"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("single credentialSubject with non-zero index does not match", func(t *testing.T) {
		// When credentialSubject is a single object and the path uses index 5,
		// this should not match — only index 0 is valid for a single element.
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"patientId": "123"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", 5, "patientId"}, Values: []any{"123"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("null wildcard on non-array value does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"name": "John"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// null wildcard on a string value — not an array
				{Path: []any{"credentialSubject", "name", nil}, Values: []any{"John"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("integer index on non-array value does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"name": "John"},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "name", 0}, Values: []any{"John"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("out-of-bounds array index does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"roles": []any{"01.015"}},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				{Path: []any{"credentialSubject", "roles", 99}, Values: []any{"01.015"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("string key on non-map non-array value does not match", func(t *testing.T) {
		credential := vc.VerifiableCredential{
			CredentialSubject: []map[string]any{
				{"count": float64(42)},
			},
		}
		query := CredentialQuery{
			ID: "test",
			Claims: []ClaimsQuery{
				// Trying to use a string key on a number
				{Path: []any{"credentialSubject", "count", "sub"}, Values: []any{"x"}},
			},
		}

		result, err := Match(query, []vc.VerifiableCredential{credential})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("valid credential query ID with hyphens and underscores", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "id_patient-enrollment_01",
			Claims: []ClaimsQuery{},
		}

		result, err := Match(query, []vc.VerifiableCredential{})

		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

func BenchmarkMatch_2000Credentials(b *testing.B) {
	const count = 2000
	roleCodes := []string{"01.015", "30.000", "17.000", "04.000", "89.000"}
	credentials := make([]vc.VerifiableCredential, count)
	for i := range credentials {
		bsn := fmt.Sprintf("%09d", i)
		ura := fmt.Sprintf("URA-%05d", i)
		// Each credential has multiple identifiers and multiple qualifications with role codes
		credentials[i] = vc.VerifiableCredential{
			Type:   []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("PatientEnrollmentCredential")},
			Issuer: ssi.MustParseURI(fmt.Sprintf("did:x509:0:sha256:hash%d", i)),
			CredentialSubject: []map[string]any{
				{
					"identifier": []any{
						map[string]any{"system": "http://fhir.nl/fhir/NamingSystem/ura", "value": ura},
						map[string]any{"system": "http://fhir.nl/fhir/NamingSystem/bsn", "value": bsn},
					},
					"qualifications": []any{
						map[string]any{"roleCode": roleCodes[i%len(roleCodes)], "name": "Role A"},
						map[string]any{"roleCode": roleCodes[(i+1)%len(roleCodes)], "name": "Role B"},
						map[string]any{"roleCode": roleCodes[(i+2)%len(roleCodes)], "name": "Role C"},
					},
				},
			},
		}
	}
	// Worst case: target is the last credential. Multiple claims with wildcards.
	targetBsn := fmt.Sprintf("%09d", count-1)
	query := CredentialQuery{
		ID: "id_patient_enrollment",
		Claims: []ClaimsQuery{
			// Wildcard over identifiers to find BSN
			{
				Path:   []any{"credentialSubject", "identifier", nil, "value"},
				Values: []any{targetBsn},
			},
			// Wildcard over qualifications to find a specific role code
			{
				Path:   []any{"credentialSubject", "qualifications", nil, "roleCode"},
				Values: []any{roleCodes[(count-1)%len(roleCodes)]},
			},
		},
	}

	b.ResetTimer()
	var benchResult []vc.VerifiableCredential
	var benchErr error
	for b.Loop() {
		benchResult, benchErr = Match(query, credentials)
	}
	require.NoError(b, benchErr)
	require.Len(b, benchResult, 1)
}
