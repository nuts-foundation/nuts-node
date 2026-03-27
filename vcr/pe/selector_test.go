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
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFieldSelector(t *testing.T) {
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	vc1 := credentialToJSONLD(vc.VerifiableCredential{ID: &id1, CredentialSubject: []map[string]any{{"patientId": "123"}}})
	vc2 := credentialToJSONLD(vc.VerifiableCredential{ID: &id2, CredentialSubject: []map[string]any{{"patientId": "456"}}})
	pd := PresentationDefinition{
		InputDescriptors: []*InputDescriptor{
			{
				Id: "patient_credential",
				Constraints: &Constraints{
					Fields: []Field{
						{
							Id:   to.Ptr("patient_id"),
							Path: []string{"$.credentialSubject.patientId"},
						},
					},
				},
			},
		},
	}

	t.Run("selection picks the right credential by field value", func(t *testing.T) {
		selector, err := NewFieldSelector(map[string]string{
			"patient_id": "456",
		}, pd)
		require.NoError(t, err)

		result, err := selector(
			*pd.InputDescriptors[0],
			[]vc.VerifiableCredential{vc1, vc2},
		)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, &id2, result.ID)
	})
	t.Run("zero matches returns ErrNoCredentials", func(t *testing.T) {
		selector, err := NewFieldSelector(map[string]string{
			"patient_id": "nonexistent",
		}, pd)
		require.NoError(t, err)

		_, err = selector(
			*pd.InputDescriptors[0],
			[]vc.VerifiableCredential{vc1, vc2},
		)

		assert.ErrorIs(t, err, ErrNoCredentials)
	})
	t.Run("multiple matches returns ErrMultipleCredentials", func(t *testing.T) {
		// Both VCs have a patientId field — selecting on a field that exists in both
		// without narrowing to one should fail.
		id3 := ssi.MustParseURI("3")
		vc3 := credentialToJSONLD(vc.VerifiableCredential{ID: &id3, CredentialSubject: []map[string]any{{"patientId": "456"}}})
		selector, err := NewFieldSelector(map[string]string{
			"patient_id": "456",
		}, pd)
		require.NoError(t, err)

		_, err = selector(
			*pd.InputDescriptors[0],
			[]vc.VerifiableCredential{vc2, vc3},
		)

		assert.ErrorIs(t, err, ErrMultipleCredentials)
	})
	t.Run("unknown selection key returns construction error", func(t *testing.T) {
		_, err := NewFieldSelector(map[string]string{
			"nonexistent_field": "value",
		}, pd)

		assert.ErrorContains(t, err, "nonexistent_field")
	})
	t.Run("no selection keys for descriptor returns nil nil", func(t *testing.T) {
		// Selection targets patient_credential, but we call with a different descriptor.
		selector, err := NewFieldSelector(map[string]string{
			"patient_id": "456",
		}, pd)
		require.NoError(t, err)

		otherDescriptor := InputDescriptor{Id: "other_descriptor"}
		result, err := selector(
			otherDescriptor,
			[]vc.VerifiableCredential{vc1, vc2},
		)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})
	t.Run("multiple selection keys use AND semantics", func(t *testing.T) {
		andPD := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "enrollment",
					Constraints: &Constraints{
						Fields: []Field{
							{Id: to.Ptr("patient_id"), Path: []string{"$.credentialSubject.patientId"}},
							{Id: to.Ptr("org_city"), Path: []string{"$.credentialSubject.city"}},
						},
					},
				},
			},
		}
		// vc matching both criteria
		idA := ssi.MustParseURI("A")
		vcA := credentialToJSONLD(vc.VerifiableCredential{ID: &idA, CredentialSubject: []map[string]any{{"patientId": "123", "city": "Amsterdam"}}})
		// vc matching only patient_id
		idB := ssi.MustParseURI("B")
		vcB := credentialToJSONLD(vc.VerifiableCredential{ID: &idB, CredentialSubject: []map[string]any{{"patientId": "123", "city": "Rotterdam"}}})

		selector, err := NewFieldSelector(map[string]string{
			"patient_id": "123",
			"org_city":   "Amsterdam",
		}, andPD)
		require.NoError(t, err)

		result, err := selector(
			*andPD.InputDescriptors[0],
			[]vc.VerifiableCredential{vcA, vcB},
		)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, &idA, result.ID)
	})
	t.Run("multiple descriptors with independent selection keys", func(t *testing.T) {
		multiPD := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "org_credential",
					Constraints: &Constraints{
						Fields: []Field{
							{Id: to.Ptr("ura"), Path: []string{"$.credentialSubject.ura"}},
						},
					},
				},
				{
					Id: "patient_enrollment",
					Constraints: &Constraints{
						Fields: []Field{
							{Id: to.Ptr("bsn"), Path: []string{"$.credentialSubject.bsn"}},
						},
					},
				},
			},
		}
		idA := ssi.MustParseURI("A")
		idB := ssi.MustParseURI("B")
		idC := ssi.MustParseURI("C")
		idD := ssi.MustParseURI("D")
		vcA := credentialToJSONLD(vc.VerifiableCredential{ID: &idA, CredentialSubject: []map[string]any{{"ura": "URA-001"}}})
		vcB := credentialToJSONLD(vc.VerifiableCredential{ID: &idB, CredentialSubject: []map[string]any{{"ura": "URA-002"}}})
		vcC := credentialToJSONLD(vc.VerifiableCredential{ID: &idC, CredentialSubject: []map[string]any{{"bsn": "BSN-111"}}})
		vcD := credentialToJSONLD(vc.VerifiableCredential{ID: &idD, CredentialSubject: []map[string]any{{"bsn": "BSN-222"}}})

		selector, err := NewFieldSelector(map[string]string{
			"ura": "URA-002",
			"bsn": "BSN-111",
		}, multiPD)
		require.NoError(t, err)

		// First descriptor: selects vcB (URA-002)
		result, err := selector(
			*multiPD.InputDescriptors[0],
			[]vc.VerifiableCredential{vcA, vcB},
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, &idB, result.ID)

		// Second descriptor: selects vcC (BSN-111)
		result, err = selector(
			*multiPD.InputDescriptors[1],
			[]vc.VerifiableCredential{vcC, vcD},
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, &idC, result.ID)
	})
}
