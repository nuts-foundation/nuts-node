/*
 * Copyright (C) 2024 Nuts community
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

package iam

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/v6/vcr/pe"
	"github.com/nuts-foundation/nuts-node/v6/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOpenID4VPVerifier_next(t *testing.T) {
	userPresentationDefinition := PresentationDefinition{
		Id: "user",
	}
	orgPresentationDefinition := PresentationDefinition{
		Id: "organization",
	}
	t.Run("owner is next", func(t *testing.T) {
		v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
			pe.WalletOwnerOrganization: orgPresentationDefinition,
			pe.WalletOwnerUser:         userPresentationDefinition,
		})
		ownerType, definition := v.next()
		assert.Equal(t, pe.WalletOwnerOrganization, *ownerType)
		assert.Equal(t, orgPresentationDefinition, *definition)

	})
	t.Run("user is next", func(t *testing.T) {
		v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
			pe.WalletOwnerOrganization: orgPresentationDefinition,
			pe.WalletOwnerUser:         userPresentationDefinition,
		})
		v.Submissions[orgPresentationDefinition.Id] = PresentationSubmission{}
		ownerType, definition := v.next()
		assert.Equal(t, pe.WalletOwnerUser, *ownerType)
		assert.Equal(t, userPresentationDefinition, *definition)
	})
	t.Run("no next", func(t *testing.T) {
		v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
			pe.WalletOwnerOrganization: orgPresentationDefinition,
			pe.WalletOwnerUser:         userPresentationDefinition,
		})
		v.Submissions = map[string]PresentationSubmission{
			orgPresentationDefinition.Id:  {},
			userPresentationDefinition.Id: {},
		}
		ownerType, definition := v.next()
		assert.Nil(t, ownerType)
		assert.Nil(t, definition)
	})
}

func TestPEXConsumer_Marshalling(t *testing.T) {
	consumer := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
		pe.WalletOwnerOrganization: {
			Id: "organization",
		},
	})
	expectedEnvelopeJSON := []byte(`{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "id": "did:web:nodeB#639f78bf-a95b-4ffd-92de-bf4031a456ed",
  "proof": {
    "challenge": "vbyZ6EVMhK4A5zv0V3S97vGwJe3khUBw2Z46ui0hm5U",
    "created": "2024-04-19T10:09:18.649110584Z",
    "domain": "did:web:nodeA",
    "expires": "2024-04-19T10:24:18.648767413Z",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6bm9kZUIjMCJ9..Abx-L1yXkcSkL8Ec8Md0fQ5kqn_AmMD_6cGuiC_mSMWzOxTz3lRZpDttGdx4GIxprAGqK4mSupIqjcpBuK7Gkg",
    "nonce": "vbyZ6EVMhK4A5zv0V3S97vGwJe3khUBw2Z46ui0hm5U",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:nodeB#0"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://nuts.nl/credentials/v1",
      "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
      "id": "did:web:nodeB",
      "organization": {
        "city": "Caretown",
        "name": "Caresoft+B.V."
      }
    },
    "id": "did:web:nodeB#8f29c638-3c31-448b-9da6-6cd44def9c10",
    "issuanceDate": "2024-04-19T10:09:18.554015056Z",
    "issuer": "did:web:nodeB",
    "proof": {
      "created": "2024-04-19T10:09:18.554015056Z",
      "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6bm9kZUIjMCJ9..hFr9XnrazNDbDz9YzydA12otVUdkrUtN5PqxMbUVj5SL3UpEAYDUOLaLOEKfckGtzseUI9O2Y-i04CdlohonYw",
      "proofPurpose": "assertionMethod",
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:web:nodeB#0"
    },
    "type": [
      "NutsOrganizationCredential",
      "VerifiableCredential"
    ]
  }
}`)
	// normalize JSON to ease comparison
	m := make(map[string]interface{})
	err := json.Unmarshal(expectedEnvelopeJSON, &m)
	require.NoError(t, err)
	expectedEnvelopeJSON, _ = json.Marshal(m)

	envelope, _ := pe.ParseEnvelope(expectedEnvelopeJSON)
	err = consumer.fulfill(PresentationSubmission{DefinitionId: "organization"}, *envelope)

	require.NoError(t, err)

	asJSON, _ := json.Marshal(consumer)
	var actual PEXConsumer
	err = json.Unmarshal(asJSON, &actual)
	require.NoError(t, err)

	assert.Equal(t, consumer.RequiredPresentationDefinitions, actual.RequiredPresentationDefinitions)
	assert.Equal(t, consumer.Submissions, actual.Submissions)
	assert.Equal(t, consumer.SubmittedEnvelopes, actual.SubmittedEnvelopes)
}

func TestPEXConsumer_fulfill(t *testing.T) {
	userPresentationDefinition := PresentationDefinition{
		Id: "user",
	}
	orgPresentationDefinition := PresentationDefinition{
		Id: "organization",
	}
	t.Run("ok", func(t *testing.T) {
		v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
			pe.WalletOwnerOrganization: orgPresentationDefinition,
		})
		err := v.fulfill(PresentationSubmission{DefinitionId: orgPresentationDefinition.Id}, pe.Envelope{})
		require.NoError(t, err)
	})
	t.Run("not required", func(t *testing.T) {
		v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{
			pe.WalletOwnerUser: userPresentationDefinition,
		})
		err := v.fulfill(PresentationSubmission{Id: userPresentationDefinition.Id}, pe.Envelope{})
		assert.Error(t, err)
	})
	t.Run("already fulfilled", func(t *testing.T) {
		v := PEXConsumer{
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
			},
			Submissions: map[string]PresentationSubmission{
				orgPresentationDefinition.Id: {},
			},
		}
		err := v.fulfill(PresentationSubmission{Id: orgPresentationDefinition.Id}, pe.Envelope{})
		assert.Error(t, err)
	})
	t.Run("fields sharing an id carry different values", func(t *testing.T) {
		definition := PresentationDefinition{
			Id: "shared_id",
			InputDescriptors: []*pe.InputDescriptor{
				sharedIDInputDescriptor("organization", "Organization"),
				sharedIDInputDescriptor("delegation", "Delegation"),
			},
		}
		subjectDID := did.MustParseDID("did:web:example.com")
		credentialWith := func(kind string, ura any) vc.VerifiableCredential {
			return vc.VerifiableCredential{CredentialSubject: []map[string]any{{"id": subjectDID.String(), "kind": kind, "ura": ura}}}
		}
		submission := PresentationSubmission{DefinitionId: definition.Id, DescriptorMap: []pe.InputDescriptorMappingObject{
			{Id: "organization", Path: "$.verifiableCredential[0]", Format: vc.JSONLDCredentialProofFormat},
			{Id: "delegation", Path: "$.verifiableCredential[1]", Format: vc.JSONLDCredentialProofFormat},
		}}
		envelopeWith := func(t *testing.T, credentials ...vc.VerifiableCredential) pe.Envelope {
			presentation := test.CreateJSONLDPresentation(t, subjectDID, nil, credentials...)
			envelope, err := pe.ParseEnvelope([]byte(presentation.Raw()))
			require.NoError(t, err)
			return *envelope
		}
		t.Run("values differ", func(t *testing.T) {
			v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{pe.WalletOwnerOrganization: definition})

			err := v.fulfill(submission, envelopeWith(t, credentialWith("Organization", "1"), credentialWith("Delegation", "2")))

			require.ErrorIs(t, err, pe.ErrConflictingFieldValues)
			assert.EqualError(t, err, "presentation does not conform to presentation definition (id=shared_id): fields sharing an id resolve to different values: field id 'ura' in input descriptors 'organization' and 'delegation'")
			assert.False(t, v.isFulfilled(definition.Id))
		})
		t.Run("values agree", func(t *testing.T) {
			v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{pe.WalletOwnerOrganization: definition})

			err := v.fulfill(submission, envelopeWith(t, credentialWith("Organization", "1"), credentialWith("Delegation", "1")))

			require.NoError(t, err)
			assert.True(t, v.isFulfilled(definition.Id))
		})
		t.Run("incorrect mapping without differing values - rejected by validation", func(t *testing.T) {
			v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{pe.WalletOwnerOrganization: definition})
			swapped := PresentationSubmission{DefinitionId: definition.Id, DescriptorMap: []pe.InputDescriptorMappingObject{
				{Id: "organization", Path: "$.verifiableCredential[1]", Format: vc.JSONLDCredentialProofFormat},
				{Id: "delegation", Path: "$.verifiableCredential[0]", Format: vc.JSONLDCredentialProofFormat},
			}}

			err := v.fulfill(swapped, envelopeWith(t, credentialWith("Organization", "1"), credentialWith("Delegation", "1")))

			assert.EqualError(t, err, "presentation submission does not conform to presentation definition (id=shared_id)")
			assert.False(t, v.isFulfilled(definition.Id))
		})
		t.Run("array values", func(t *testing.T) {
			// the same input descriptors, but "ura" accepts any value, so it can resolve to an array
			anyURA := func(id string, kind string) *pe.InputDescriptor {
				descriptor := sharedIDInputDescriptor(id, kind)
				descriptor.Constraints.Fields[1].Filter = nil
				return descriptor
			}
			arrayDefinition := PresentationDefinition{
				Id:               definition.Id,
				InputDescriptors: []*pe.InputDescriptor{anyURA("organization", "Organization"), anyURA("delegation", "Delegation")},
			}
			t.Run("differ", func(t *testing.T) {
				v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{pe.WalletOwnerOrganization: arrayDefinition})

				err := v.fulfill(submission, envelopeWith(t, credentialWith("Organization", []any{"1", "2"}), credentialWith("Delegation", []any{"1", "3"})))

				require.ErrorIs(t, err, pe.ErrConflictingFieldValues)
				assert.ErrorContains(t, err, "field id 'ura' in input descriptors 'organization' and 'delegation'")
				assert.False(t, v.isFulfilled(definition.Id))
			})
			t.Run("agree", func(t *testing.T) {
				v := newPEXConsumer(map[pe.WalletOwnerType]pe.PresentationDefinition{pe.WalletOwnerOrganization: arrayDefinition})

				err := v.fulfill(submission, envelopeWith(t, credentialWith("Organization", []any{"1", "2"}), credentialWith("Delegation", []any{"1", "2"})))

				require.NoError(t, err)
				assert.True(t, v.isFulfilled(definition.Id))
			})
		})
	})
}
