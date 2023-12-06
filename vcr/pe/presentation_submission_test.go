/*
 * Copyright (C) 2023 Nuts community
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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe/test"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestParsePresentationSubmission(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		submission, err := ParsePresentationSubmission([]byte(`{"id": "1", "definition_id":"1", "descriptor_map": []}`))
		require.NoError(t, err)
		assert.Equal(t, "1", submission.Id)
	})
	t.Run("missing id", func(t *testing.T) {
		_, err := ParsePresentationSubmission([]byte(`{"definition_id":"1", "descriptor_map": []}`))
		assert.ErrorContains(t, err, `missing properties: "id"`)
	})
}

func TestPresentationSubmissionBuilder_Build(t *testing.T) {
	holder1 := did.MustParseDID("did:example:1")
	holder2 := did.MustParseDID("did:example:2")
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	id3 := ssi.MustParseURI("3")
	vc1 := credentialToJSONLD(vc.VerifiableCredential{ID: &id1})
	vc2 := credentialToJSONLD(vc.VerifiableCredential{ID: &id2})
	vc3 := credentialToJSONLD(vc.VerifiableCredential{ID: &id3})

	t.Run("1 presentation with 1 credential", func(t *testing.T) {
		expectedJSON := `
		{
		 "id": "for-test",
		 "definition_id": "",
		 "descriptor_map": [
		   {
		     "format": "ldp_vc",
		     "id": "Match ID=1",
		     "path": "$.verifiableCredential"
		   }
		 ]
		}`
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.PickOne), &presentationDefinition)
		builder := presentationDefinition.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1, vc2})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 1)
		require.Len(t, submission.DescriptorMap, 1)
		assert.Equal(t, "$.verifiableCredential", submission.DescriptorMap[0].Path)

		submission.Id = "for-test" // easier assertion
		actualJSON, _ := json.MarshalIndent(submission, "", "  ")
		println(string(actualJSON))
		assert.JSONEq(t, expectedJSON, string(actualJSON))
	})
	t.Run("1 presentation with 2 credentials", func(t *testing.T) {
		expectedJSON := `
		{
		 "id": "for-test",
		 "definition_id": "",
		 "descriptor_map": [
		   {
		     "format": "ldp_vc",
		     "id": "Match ID=1",
		     "path": "$.verifiableCredential[0]"
		   },
		   {
		     "format": "ldp_vc",
		     "id": "Match ID=2",
		     "path": "$.verifiableCredential[1]"
		   }
		 ]
		}`
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.All), &presentationDefinition)
		builder := presentationDefinition.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1, vc2})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 1)
		require.Len(t, submission.DescriptorMap, 2)

		submission.Id = "for-test" // easier assertion
		actualJSON, _ := json.MarshalIndent(submission, "", "  ")
		println(string(actualJSON))
		assert.JSONEq(t, expectedJSON, string(actualJSON))
	})
	t.Run("2 presentations", func(t *testing.T) {
		expectedJSON := `
{
  "id": "for-test",
  "definition_id": "",
  "descriptor_map": [
    {
      "format": "ldp_vp",
      "id": "Match ID=1",
      "path": "$[0]",
      "path_nested": {
        "format": "ldp_vc",
        "id": "Match ID=1",
        "path": "$.verifiableCredential"
      }
    },
    {
      "format": "ldp_vp",
      "id": "Match ID=2",
      "path": "$[1]",
      "path_nested": {
        "format": "ldp_vc",
        "id": "Match ID=2",
        "path": "$.verifiableCredential"
      }
    }
  ]
}
`
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.All), &presentationDefinition)
		builder := presentationDefinition.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1})
		builder.AddWallet(holder2, []vc.VerifiableCredential{vc2})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 2)
		assert.Len(t, submission.DescriptorMap, 2)

		submission.Id = "for-test" // easier assertion
		actualJSON, _ := json.MarshalIndent(submission, "", "  ")
		assert.JSONEq(t, expectedJSON, string(actualJSON))
	})
	t.Run("2 wallets, but 1 VP", func(t *testing.T) {
		expectedJSON := `
		{
		 "id": "for-test",
		 "definition_id": "",
		 "descriptor_map": [
		   {
		     "format": "ldp_vc",
		     "id": "Match ID=1",
		     "path": "$.verifiableCredential[0]"
		   },
		   {
		     "format": "ldp_vc",
		     "id": "Match ID=2",
		     "path": "$.verifiableCredential[1]"
		   }
		 ]
		}`
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.All), &presentationDefinition)
		builder := presentationDefinition.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1, vc2})
		builder.AddWallet(holder2, []vc.VerifiableCredential{vc3})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 1)
		assert.Len(t, submission.DescriptorMap, 2)

		submission.Id = "for-test" // easier assertion
		actualJSON, _ := json.MarshalIndent(submission, "", "  ")
		assert.JSONEq(t, expectedJSON, string(actualJSON))
	})
}

func TestPresentationSubmission_Resolve(t *testing.T) {
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	now := time.Now()
	vc1 := credentialToJSONLD(vc.VerifiableCredential{
		ID:             &id1,
		ExpirationDate: &now,
		CredentialSubject: []interface{}{
			map[string]interface{}{
				// weird field for testing error case: parsing credentialSubject as JSON-LD Verifiable Credential
				// (expirationDate must be a JSON string containing a valid XML date-time)
				"expirationDate": "yesterday",
				// weird field for testing error case: parsing credentialSubject as JSON-LD Verifiable Presentation
				// (holder must be a JSON string containing a URI)
				"holder": []string{"1", "2"},
				"name":   "John Doe",
			},
		},
	})
	vc2 := credentialToJSONLD(vc.VerifiableCredential{ID: &id2})
	//vc3 := credentialToJSONLD(vc.VerifiableCredential{ID: &id3})

	t.Run("1 presentation, JSON-LD", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vc",
      "id": "1",
      "path": "$.verifiableCredential"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		require.NoError(t, err)
		assert.Len(t, credentials, 1)
		assert.Equal(t, vc1.ID, credentials["1"].ID)
	})
	t.Run("2 credentials, JSON-LD", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1, vc2},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vc",
      "id": "1",
      "path": "$.verifiableCredential[0]"
    },
    {
      "format": "ldp_vc",
      "id": "2",
      "path": "$.verifiableCredential[1]"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		require.NoError(t, err)
		assert.Len(t, credentials, 2)
		assert.Equal(t, vc1.ID, credentials["1"].ID)
		assert.Equal(t, vc2.ID, credentials["2"].ID)
	})
	t.Run("2 presentations, JSON-LD", func(t *testing.T) {
		vp1 := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		vp2 := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc2},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vp",
      "id": "1",
      "path": "$[0]",
      "path_nested": {
        "id": "1",
        "format": "ldp_vc",
        "path": "$.verifiableCredential"
      }
    },
    {
      "format": "ldp_vp",
      "id": "2",
      "path": "$[1]",
      "path_nested": {
        "id": "2",
        "format": "ldp_vc",
        "path": "$.verifiableCredential"
      }
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, []interface{}{vp1, vp2}))

		require.NoError(t, err)
		assert.Len(t, credentials, 2)
		assert.Equal(t, vc1.ID, credentials["1"].ID)
		assert.Equal(t, vc2.ID, credentials["2"].ID)
	})
	t.Run("expected credential, got presentation", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vp",
      "id": "1",
      "path": "$.verifiableCredential"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		require.EqualError(t, err, "unable to resolve credential for input descriptor '1': path '$.verifiableCredential' does not reference a credential")
		assert.Nil(t, credentials)
	})
	t.Run("invalid JSON-LD credential", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vc",
      "id": "1",
      "path": "$.verifiableCredential.credentialSubject"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		require.ErrorContains(t, err, "unable to resolve credential for input descriptor '1': invalid JSON-LD credential at path")
		assert.Nil(t, credentials)
	})
	t.Run("invalid JSON-LD presentation", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vp",
      "id": "1",
      "path": "$.verifiableCredential.credentialSubject"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		require.ErrorContains(t, err, "unable to resolve credential for input descriptor '1': invalid JSON-LD presentation at path")
		assert.Nil(t, credentials)
	})
	t.Run("path does not resolve to a VP or VC", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{vc1},
		}
		const submissionJSON = `
{
  "descriptor_map": [
    {
      "format": "ldp_vc",
      "id": "1",
      "path": "$.verifiableCredential.expirationDate"
    }
  ]
}
`
		var submission PresentationSubmission
		require.NoError(t, json.Unmarshal([]byte(submissionJSON), &submission))

		credentials, err := submission.Resolve(toEnvelope(t, vp))

		assert.EqualError(t, err, "unable to resolve credential for input descriptor '1': value of Go type 'string' at path '$.verifiableCredential.expirationDate' can't be decoded using format 'ldp_vc'")
		assert.Nil(t, credentials)
	})
}

func TestPresentationSubmission_Validate(t *testing.T) {
	vcID := ssi.MustParseURI("did:example:123#first-vc")
	vp := vc.VerifiablePresentation{
		VerifiableCredential: []vc.VerifiableCredential{
			credentialToJSONLD(vc.VerifiableCredential{ID: &vcID}),
		},
		Proof: []interface{}{
			proof.LDProof{VerificationMethod: vcID},
		},
	}

	t.Run("ok - 1 presentation", func(t *testing.T) {
		constant := vcID.String()
		definition := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &constant,
								},
							},
						},
					},
				},
			},
		}
		submission := PresentationSubmission{
			DescriptorMap: []InputDescriptorMappingObject{
				{
					Id:     "1",
					Path:   "$.verifiableCredential",
					Format: "ldp_vc",
				},
			},
		}

		credentials, err := submission.Validate(toEnvelope(t, vp), definition)

		require.NoError(t, err)
		require.Len(t, credentials, 1)
		assert.Equal(t, vcID.String(), credentials["1"].ID.String())
	})
	t.Run("ok - 2 presentations", func(t *testing.T) {
		constant1 := vcID.String()
		secondVCID := ssi.MustParseURI("did:example:123#second-vc")
		constant2 := secondVCID.String()
		secondVP := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{
				{ID: &secondVCID},
			},
			Proof: []interface{}{
				proof.LDProof{VerificationMethod: vcID},
			},
		}
		definition := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &constant1,
								},
							},
						},
					},
				},
				{
					Id: "2",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &constant2,
								},
							},
						},
					},
				},
			},
		}
		submission := PresentationSubmission{
			DescriptorMap: []InputDescriptorMappingObject{
				{
					Id:     "1",
					Path:   "$[0]",
					Format: "ldp_vp",
					PathNested: &InputDescriptorMappingObject{
						Id:     "1",
						Path:   "$.verifiableCredential",
						Format: "ldp_vc",
					},
				},
				{
					Id:     "2",
					Path:   "$[1]",
					Format: "ldp_vp",
					PathNested: &InputDescriptorMappingObject{
						Id:     "2",
						Path:   "$.verifiableCredential",
						Format: "ldp_vc",
					},
				},
			},
		}

		credentials, err := submission.Validate(toEnvelope(t, []vc.VerifiablePresentation{vp, secondVP}), definition)

		require.NoError(t, err)
		require.Len(t, credentials, 2)
		assert.Equal(t, vcID.String(), credentials["1"].ID.String())
		assert.Equal(t, secondVCID.String(), credentials["2"].ID.String())
	})
	t.Run("submission mappings don't match definition input descriptors", func(t *testing.T) {
		constant := "incorrect ID"
		definition := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &constant,
								},
							},
						},
					},
				},
			},
		}

		credentials, err := PresentationSubmission{}.Validate(toEnvelope(t, []vc.VerifiablePresentation{vp}), definition)

		assert.EqualError(t, err, "presentation submission doesn't match presentation definition")
		assert.Empty(t, credentials)
	})
	t.Run("credentials match wrong input descriptors", func(t *testing.T) {
		incorrectID := "incorrect ID"
		correctID := vcID.String()
		count := 1
		definition := PresentationDefinition{
			SubmissionRequirements: []*SubmissionRequirement{
				{
					Name:  "pick",
					Count: &count,
					From:  "any",
					Rule:  "pick",
				},
			},
			InputDescriptors: []*InputDescriptor{
				{
					Id:    "1",
					Group: []string{"any"},
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &incorrectID,
								},
							},
						},
					},
				},
				{
					Id:    "2",
					Group: []string{"any"},
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type:  "string",
									Const: &correctID,
								},
							},
						},
					},
				},
			},
		}
		submission := PresentationSubmission{
			DescriptorMap: []InputDescriptorMappingObject{
				{
					Id:     "1", // actually maps to input descriptor 2, so should cause an error
					Path:   "$.verifiableCredential",
					Format: "ldp_vc",
				},
			},
		}

		credentials, err := submission.Validate(toEnvelope(t, vp), definition)

		assert.EqualError(t, err, "incorrect mapping for input descriptor: 2")
		assert.Empty(t, credentials)
	})
	t.Run("submission contains mappings for non-existing input descriptors", func(t *testing.T) {
		definition := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id: "1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path: []string{"$.id"},
								Filter: &Filter{
									Type: "string",
								},
							},
						},
					},
				},
			},
		}
		submission := PresentationSubmission{
			DescriptorMap: []InputDescriptorMappingObject{
				{
					Id:     "1",
					Path:   "$.verifiableCredential[0]",
					Format: "ldp_vc",
				},
				{
					Id:     "non-existent",
					Path:   "$.verifiableCredential[1]",
					Format: "ldp_vc",
				},
			},
		}

		secondVCID := ssi.MustParseURI("did:example:123#second-vc")
		vp = vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{
				{ID: &vcID},
				{ID: &secondVCID},
			},
			Proof: []interface{}{
				proof.LDProof{VerificationMethod: vcID},
			},
		}

		credentials, err := submission.Validate(toEnvelope(t, vp), definition)

		assert.EqualError(t, err, "expected 1 credentials, got 2")
		assert.Empty(t, credentials)
	})
	t.Run("unable to derive presentation signer", func(t *testing.T) {
		vp = vc.VerifiablePresentation{}
		credentials, err := PresentationSubmission{}.Validate(toEnvelope(t, vp), PresentationDefinition{})

		assert.EqualError(t, err, "unable to derive presentation signer: presentation should have exactly 1 proof, got 0")
		assert.Empty(t, credentials)
	})
}

func toEnvelope(t *testing.T, presentations interface{}) Envelope {
	vpBytes, _ := json.Marshal(presentations)
	envelope, err := ParseEnvelope(vpBytes)
	require.NoError(t, err)
	return *envelope
}
