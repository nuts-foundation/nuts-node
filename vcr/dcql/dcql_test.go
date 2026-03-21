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
	"testing"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
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
					Path:   []string{"credentialSubject", "patientId"},
					Values: []any{"123456789"},
				},
			},
		}

		result := Match(query, []vc.VerifiableCredential{credential})

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
					Path:   []string{"credentialSubject", "patientId"},
					Values: []any{"999999999"},
				},
			},
		}

		result := Match(query, []vc.VerifiableCredential{credential})

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
					Path:   []string{"credentialSubject", "hasEnrollment", "patient", "identifier", "value"},
					Values: []any{"123456789"},
				},
			},
		}

		result := Match(query, []vc.VerifiableCredential{credential})

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
					Path:   []string{"credentialSubject", "postalCode"},
					Values: []any{"90210", "90211"},
				},
			},
		}

		result := Match(query, []vc.VerifiableCredential{credential})

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
					Path:   []string{"credentialSubject", "postalCode"},
					Values: []any{"90210", "90211"},
				},
			},
		}

		result := Match(query, []vc.VerifiableCredential{credential})

		assert.Empty(t, result)
	})
}
