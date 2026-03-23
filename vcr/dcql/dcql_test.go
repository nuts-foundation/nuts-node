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

		assert.EqualError(t, err, "invalid credential query id: must consist of alphanumeric, underscore, or hyphen characters")
	})
	t.Run("empty credential query ID returns error", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "",
			Claims: []ClaimsQuery{},
		}

		_, err := Match(query, []vc.VerifiableCredential{})

		assert.EqualError(t, err, "invalid credential query id: must be a non-empty string")
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
	credentials := make([]vc.VerifiableCredential, count)
	for i := range credentials {
		bsn := fmt.Sprintf("%09d", i)
		credentials[i] = vc.VerifiableCredential{
			Type: []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("PatientEnrollmentCredential")},
			CredentialSubject: []map[string]any{
				{
					"hasEnrollment": map[string]any{
						"patient": map[string]any{
							"identifier": map[string]any{
								"system": "http://fhir.nl/fhir/NamingSystem/bsn",
								"value":  bsn,
							},
						},
					},
				},
			},
		}
	}
	// Worst case: target is the last credential
	targetBsn := fmt.Sprintf("%09d", count-1)
	query := CredentialQuery{
		ID: "id_patient_enrollment",
		Claims: []ClaimsQuery{
			{
				Path:   []any{"credentialSubject", "hasEnrollment", "patient", "identifier", "value"},
				Values: []any{targetBsn},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		Match(query, credentials)
	}
}
