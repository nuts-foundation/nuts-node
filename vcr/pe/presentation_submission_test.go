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
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/v6/vcr/pe/test"
	"github.com/nuts-foundation/nuts-node/v6/vcr/signature/proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("ldp_vp", func(t *testing.T) {

		t.Run("1 presentation without credentials", func(t *testing.T) {
			expectedJSON := `
		{
		 "id": "for-test",
		 "definition_id": "empty"
		}`
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.Empty), &presentationDefinition)
			builder := presentationDefinition.PresentationSubmissionBuilder()
			builder.AddWallet(holder1, []vc.VerifiableCredential{})

			submission, signInstruction, err := builder.Build("ldp_vp")

			require.NoError(t, err)
			assert.Len(t, signInstruction.VerifiableCredentials, 0)
			require.Len(t, submission.DescriptorMap, 0)

			submission.Id = "for-test" // easier assertion
			actualJSON, _ := json.MarshalIndent(submission, "", "  ")
			assert.JSONEq(t, expectedJSON, string(actualJSON))
		})

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

			submission, signInstruction, err := builder.Build("ldp_vp")

			require.NoError(t, err)
			assert.Len(t, signInstruction.VerifiableCredentials, 1)
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

			submission, signInstruction, err := builder.Build("ldp_vp")

			require.NoError(t, err)
			assert.Len(t, signInstruction.VerifiableCredentials, 2)
			require.Len(t, submission.DescriptorMap, 2)

			submission.Id = "for-test" // easier assertion
			actualJSON, _ := json.MarshalIndent(submission, "", "  ")
			println(string(actualJSON))
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

			submission, signInstruction, err := builder.Build("ldp_vp")

			require.NoError(t, err)
			assert.Len(t, signInstruction.VerifiableCredentials, 2)
			assert.Len(t, submission.DescriptorMap, 2)

			submission.Id = "for-test" // easier assertion
			actualJSON, _ := json.MarshalIndent(submission, "", "  ")
			assert.JSONEq(t, expectedJSON, string(actualJSON))
		})
	})
	t.Run("jwt_vp", func(t *testing.T) {
		t.Run("1 presentation with 1 credential", func(t *testing.T) {
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.PickOne), &presentationDefinition)
			builder := presentationDefinition.PresentationSubmissionBuilder()
			builder.AddWallet(holder1, []vc.VerifiableCredential{vc1, vc2})

			submission, signInstruction, err := builder.Build("jwt_vp")

			require.NoError(t, err)
			assert.Len(t, signInstruction.VerifiableCredentials, 1)
			assert.Equal(t, holder1, signInstruction.Holder)
			require.Len(t, submission.DescriptorMap, 1)
			assert.Equal(t, "$.verifiableCredential[0]", submission.DescriptorMap[0].Path)
		})
	})
}

func TestPresentationSubmissionBuilder_SetCredentialSelection(t *testing.T) {
	holder1 := did.MustParseDID("did:example:1")
	holder2 := did.MustParseDID("did:example:2")
	vcA := selectionCredential("A", map[string]any{"kind": "provider", "ura": "1", "name": "Org A"})
	vcB := selectionCredential("B", map[string]any{"kind": "provider", "ura": "2", "name": "Org B"})
	vcC := selectionCredential("C", map[string]any{"kind": "provider", "ura": "3", "name": "Org B"})
	pd := PresentationDefinition{
		Id: "test",
		InputDescriptors: []*InputDescriptor{
			selectionDescriptor("provider", "provider", idField("ura", "ura"), idField("org_name", "name")),
		},
	}

	t.Run("selection picks the second credential", func(t *testing.T) {
		builder := pd.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vcA, vcB})
		builder.SetCredentialSelection(map[string]string{"org_name": "Org B"})

		_, signInstruction, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.Len(t, signInstruction.VerifiableCredentials, 1)
		assert.Equal(t, "B", signInstruction.VerifiableCredentials[0].ID.String())
	})
	t.Run("without selection uses first match (default)", func(t *testing.T) {
		builder := pd.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vcA, vcB})

		_, signInstruction, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.Len(t, signInstruction.VerifiableCredentials, 1)
		assert.Equal(t, "A", signInstruction.VerifiableCredentials[0].ID.String())
	})
	t.Run("ErrMultipleCredentials propagates", func(t *testing.T) {
		builder := pd.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vcA, vcB, vcC})
		builder.SetCredentialSelection(map[string]string{"org_name": "Org B"})

		_, _, err := builder.Build("ldp_vp")

		assert.ErrorIs(t, err, ErrMultipleCredentials)
		assert.ErrorContains(t, err, "input descriptor 'provider'")
	})
	t.Run("values chosen for one wallet do not carry over to the next wallet", func(t *testing.T) {
		// The first wallet has a provider credential (ura 1) but no delegation for it, so it fails. Had its ura
		// carried over, the second wallet (ura 2) would fail too.
		pd := PresentationDefinition{
			Id: "test",
			InputDescriptors: []*InputDescriptor{
				selectionDescriptor("provider", "provider", idField("ura", "ura")),
				selectionDescriptor("delegation", "delegation", idField("ura", "ura")),
			},
		}
		builder := pd.PresentationSubmissionBuilder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vcA})
		builder.AddWallet(holder2, []vc.VerifiableCredential{
			selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2"}),
			selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2"}),
		})

		_, signInstruction, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		assert.Equal(t, holder2, signInstruction.Holder)
		require.Len(t, signInstruction.VerifiableCredentials, 2)
		assert.Equal(t, "P2", signInstruction.VerifiableCredentials[0].ID.String())
		assert.Equal(t, "D2", signInstruction.VerifiableCredentials[1].ID.String())
	})
}

func TestPresentationSubmission_Validate_CredentialSelectionRoundTrip(t *testing.T) {
	// The verifier validates a submission by matching the presentation definition again, without the holder's
	// credential selection, against the credentials in the presentation. A presentation built with a selection
	// that made the holder pick other credentials than its first matches must still validate.
	holderDID := did.MustParseDID("did:example:holder")
	pd := PresentationDefinition{
		Id: "test",
		InputDescriptors: []*InputDescriptor{
			selectionDescriptor("provider", "provider", idField("ura", "ura"), idField("org_name", "name")),
			selectionDescriptor("delegation", "delegation", idField("ura", "ura"), idField("employee", "employee")),
		},
	}
	wallet := []vc.VerifiableCredential{
		selectionCredential("P1", map[string]any{"kind": "provider", "ura": "1", "name": "Org A"}),
		selectionCredential("P2", map[string]any{"kind": "provider", "ura": "2", "name": "Org B"}),
		selectionCredential("D1", map[string]any{"kind": "delegation", "ura": "1", "employee": "e1"}),
		selectionCredential("D2", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"}),
		selectionCredential("D2copy", map[string]any{"kind": "delegation", "ura": "2", "employee": "e1"}),
	}
	testCases := []struct {
		name      string
		selection map[string]string
		expected  map[string]string
	}{
		{name: "without selection", expected: map[string]string{"provider": "P1", "delegation": "D1"}},
		{name: "selection picks credentials that are not the first matches", selection: map[string]string{"org_name": "Org B"}, expected: map[string]string{"provider": "P2", "delegation": "D2"}},
		{name: "selection pins the shared id", selection: map[string]string{"ura": "2"}, expected: map[string]string{"provider": "P2", "delegation": "D2"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			builder := pd.PresentationSubmissionBuilder()
			builder.AddWallet(holderDID, wallet)
			builder.SetCredentialSelection(tc.selection)
			submission, signInstruction, err := builder.Build("ldp_vp")
			require.NoError(t, err)
			verificationMethod := ssi.MustParseURI(holderDID.String() + "#1")
			presentation := vc.VerifiablePresentation{
				VerifiableCredential: signInstruction.VerifiableCredentials,
				Proof:                []interface{}{proof.LDProof{VerificationMethod: verificationMethod}},
			}

			credentials, err := submission.Validate(toEnvelope(t, presentation), pd)

			require.NoError(t, err)
			actual := make(map[string]string)
			for descriptorID, credential := range credentials {
				actual[descriptorID] = credential.ID.String()
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestNewEnvelopeFromVP(t *testing.T) {
	t.Run("wraps a parsed VP into an Envelope that PresentationSubmission.Resolve accepts", func(t *testing.T) {
		// Caller already has a *VerifiablePresentation in memory (e.g. just built by the wallet);
		// NewEnvelopeFromVP must produce an Envelope equivalent to ParseEnvelope([]byte(vp.Raw())) so that
		// Resolve sees the same descriptor → credential mapping.
		vpRaw := `{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"type": ["VerifiablePresentation"],
			"verifiableCredential": [{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiableCredential"],
				"id": "urn:vc:42",
				"issuer": "did:test:issuer",
				"credentialSubject": {"id": "did:test:subject"},
				"proof": {"type": "JsonWebSignature2020"}
			}],
			"proof": {"type": "JsonWebSignature2020"}
		}`
		presentation, err := vc.ParseVerifiablePresentation(vpRaw)
		require.NoError(t, err)
		submission := PresentationSubmission{
			DescriptorMap: []InputDescriptorMappingObject{
				{Id: "id_org_cred", Format: "ldp_vc", Path: "$.verifiableCredential[0]"},
			},
		}

		envelope, err := NewEnvelopeFromVP(*presentation)
		require.NoError(t, err)
		credentials, err := submission.Resolve(*envelope)

		require.NoError(t, err)
		require.Contains(t, credentials, "id_org_cred")
		assert.Equal(t, "urn:vc:42", credentials["id_org_cred"].ID.String())
	})
}

func TestPresentationSubmission_Resolve(t *testing.T) {
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	now := time.Now()
	vc1 := credentialToJSONLD(vc.VerifiableCredential{
		ID:             &id1,
		ExpirationDate: &now,
		CredentialSubject: []map[string]any{
			{
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
	t.Run("ok - empty presentation and submission", func(t *testing.T) {
		emptyVP := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{VerificationMethod: vcID},
			},
		}
		credentials, err := PresentationSubmission{}.Validate(toEnvelope(t, emptyVP), PresentationDefinition{})

		require.NoError(t, err)
		assert.Empty(t, credentials)
	})
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

		assert.EqualError(t, err, "failed to match presentation definition for did:example:123: missing credentials\nconstraints not matched: no VC for InputDescriptor (1)")
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
