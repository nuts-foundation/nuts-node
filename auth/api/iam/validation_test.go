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
 */

package iam

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_validatePresentationSigner(t *testing.T) {
	signer := did.MustParseDID("did:example:123")
	vp, _ := vc.ParseVerifiablePresentation(`{"proof":[{"verificationMethod":"did:example:123#first-vm"}]}`)
	t.Run("ok - empty presentation", func(t *testing.T) {
		subjectDID, err := validatePresentationSigner(*vp, signer)

		assert.Nil(t, err)
		assert.NotNil(t, subjectDID)
	})
}

func testCredentialAndPresentation(t *testing.T) (vc.VerifiableCredential, vc.VerifiablePresentation, *did.DID) {
	verifiableCredential := test.ValidNutsOrganizationCredential(t)
	subjectDID, _ := verifiableCredential.SubjectDID()
	presentation := test.CreateJSONLDPresentation(t, *subjectDID, nil, verifiableCredential)
	return verifiableCredential, presentation, subjectDID
}

func testPresentationDefinition(t *testing.T) pe.PresentationDefinition {
	var presentationDefinition pe.PresentationDefinition
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "test-pd",
		"format": {
			"ldp_vc": {
				"proof_type": ["JsonWebSignature2020"]
			}
		},
		"input_descriptors": [{
			"id": "1",
			"constraints": {
				"fields": [{
					"path": ["$.type"],
					"filter": {
						"type": "string",
						"const": "NutsOrganizationCredential"
					}
				}]
			}
		}]
	}`), &presentationDefinition))
	return presentationDefinition
}

func TestSubmissionProfileFunc(t *testing.T) {
	ctx := context.Background()
	verifiableCredential, presentation, subjectDID := testCredentialAndPresentation(t)
	presentationDefinition := testPresentationDefinition(t)

	walletOwnerMapping := pe.WalletOwnerMapping{
		pe.WalletOwnerOrganization: presentationDefinition,
	}

	// Build submission using the presentation definition to ensure it matches
	builder := presentationDefinition.PresentationSubmissionBuilder()
	builder.AddWallet(*subjectDID, []vc.VerifiableCredential{verifiableCredential})
	submission, _, err := builder.Build("ldp_vp")
	require.NoError(t, err)

	// Create envelope by parsing the presentation (needed for proper asInterface field)
	presentationBytes, err := json.Marshal(presentation)
	require.NoError(t, err)
	envelope, err := pe.ParseEnvelope(presentationBytes)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		accessToken := &AccessToken{}
		validator := SubmissionCredentialProfile(submission, *envelope)

		err := validator(ctx, walletOwnerMapping, accessToken)

		require.NoError(t, err)
		assert.NotNil(t, accessToken.PresentationSubmissions)
		assert.NotNil(t, accessToken.PresentationDefinitions)
		assert.NotNil(t, accessToken.VPToken)
		assert.Len(t, accessToken.VPToken, 1)
		assert.Equal(t, presentation, accessToken.VPToken[0])
	})
	t.Run("credentials don't match Presentation Definition", func(t *testing.T) {
		accessToken := &AccessToken{}
		invalidSubmission := submission
		invalidSubmission.DescriptorMap[0].Path = "$.verifiableCredential[0]"
		validator := SubmissionCredentialProfile(invalidSubmission, *envelope)

		err := validator(ctx, walletOwnerMapping, accessToken)

		require.EqualError(t, err, "invalid_request - presentation submission does not conform to presentation definition (id=test-pd)")
	})
}

func TestBasicProfileFunc(t *testing.T) {
	ctx := context.Background()
	_, presentation, _ := testCredentialAndPresentation(t)
	presentationDefinition := testPresentationDefinition(t)

	walletOwnerMapping := pe.WalletOwnerMapping{
		pe.WalletOwnerOrganization: presentationDefinition,
	}

	t.Run("ok", func(t *testing.T) {
		accessToken := &AccessToken{}
		validator := BasicCredentialProfile(presentation)

		err := validator(ctx, walletOwnerMapping, accessToken)

		require.NoError(t, err)
		require.Len(t, accessToken.VPToken, 1)
		assert.Equal(t, presentation, accessToken.VPToken[0])

		t.Run("second invocation for a second scope", func(t *testing.T) {
			err := validator(ctx, walletOwnerMapping, accessToken)

			require.NoError(t, err)
			require.Len(t, accessToken.VPToken, 2)
			assert.Equal(t, presentation, accessToken.VPToken[0])
		})
	})

	t.Run("error - presentation doesn't match definition", func(t *testing.T) {
		accessToken := &AccessToken{}
		// Create a presentation with a credential that doesn't match
		otherCredential := test.JWTNutsOrganizationCredential(t, did.MustParseDID("did:web:example.com"))
		otherSubjectDID, _ := otherCredential.SubjectDID()
		invalidPresentation := test.CreateJSONLDPresentation(t, *otherSubjectDID, nil, otherCredential)

		// Create a presentation definition that requires a different credential type
		var strictDefinition pe.PresentationDefinition
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "strict-pd",
			"format": {
				"ldp_vc": {
					"proof_type": ["JsonWebSignature2020"]
				}
			},
			"input_descriptors": [{
				"id": "1",
				"constraints": {
					"fields": [{
						"path": ["$.credentialSubject.organization.city"],
						"filter": {
							"type": "string",
							"const": "NonExistentCity"
						}
					}]
				}
			}]
		}`), &strictDefinition))

		strictMapping := pe.WalletOwnerMapping{
			pe.WalletOwnerOrganization: strictDefinition,
		}

		validator := BasicCredentialProfile(invalidPresentation)
		err := validator(ctx, strictMapping, accessToken)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
		assert.Contains(t, err.Error(), "presentation does not match presentation definition")
	})

	t.Run("error - conflicting field values", func(t *testing.T) {
		// Create a presentation definition with a field ID
		var definitionWithFieldID pe.PresentationDefinition
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "test-pd-with-field",
			"format": {
				"ldp_vc": {
					"proof_type": ["JsonWebSignature2020"]
				}
			},
			"input_descriptors": [{
				"id": "1",
				"constraints": {
					"fields": [{
						"path": ["$.type"],
						"filter": {
							"type": "string",
							"const": "NutsOrganizationCredential"
						}
					},{
						"id": "city",
						"path": ["$.credentialSubject.organization.city"],
						"filter": {
							"type": "string"
						}
					}]
				}
			}]
		}`), &definitionWithFieldID))

		mappingWithField := pe.WalletOwnerMapping{
			pe.WalletOwnerOrganization: definitionWithFieldID,
		}

		accessToken := &AccessToken{
			InputDescriptorConstraintIdMap: map[string]any{
				"city": "DifferentCity",
			},
		}
		validator := BasicCredentialProfile(presentation)

		err := validator(ctx, mappingWithField, accessToken)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server_error")
		assert.Contains(t, err.Error(), "unable to fulfill presentation requirements")
	})

	t.Run("error - empty presentation", func(t *testing.T) {
		accessToken := &AccessToken{}
		emptyPresentation := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{},
		}
		validator := BasicCredentialProfile(emptyPresentation)

		err := validator(ctx, walletOwnerMapping, accessToken)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}
