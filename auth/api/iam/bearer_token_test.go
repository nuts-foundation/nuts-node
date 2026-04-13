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

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"go.uber.org/mock/gomock"

	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapper_handleTokenRequest(t *testing.T) {
	const requestedScope = "example-scope"
	const requestedScope2 = "second-scope"
	const requestedScopes = requestedScope + " " + requestedScope2
	// Create issuer DID document and keys
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerDIDDocument := did.Document{
		ID: issuerDID,
	}
	keyID := did.DIDURL{DID: issuerDID}
	keyID.Fragment = "1"
	verificationMethod, err := did.NewVerificationMethod(keyID, ssi.JsonWebKey2020, issuerDID, keyPair.Public())
	require.NoError(t, err)
	issuerDIDDocument.AddAssertionMethod(verificationMethod)

	var presentationDefinition pe.PresentationDefinition
	require.NoError(t, json.Unmarshal([]byte(`
{
	"format": {
		"ldp_vc": {
			"proof_type": [
				"JsonWebSignature2020"
			]
		}
	},
	"input_descriptors": [
		{
			"id": "1",
			"constraints": {
				"fields": [
					{
						"path": [
							"$.type"
						],
						"filter": {
				  			"type": "string",
				  			"const": "NutsOrganizationCredential"
						}
			  		}
				]
		  	}
		}
	]
}`), &presentationDefinition))

	walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerOrganization: presentationDefinition}
	var submission pe.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(`
{
  "descriptor_map": [
    {
      "id": "1",
      "path": "$.verifiableCredential",
      "format": "ldp_vc"
    }
  ]
}`), &submission))
	submissionJSONBytes, _ := json.Marshal(submission)
	submissionJSON := string(submissionJSONBytes)
	verifiableCredential := test.ValidNutsOrganizationCredential(t)
	subjectDID, _ := verifiableCredential.SubjectDID()
	proofVisitor := test.LDProofVisitor(func(proof *proof.LDProof) {
		proof.Domain = &issuerClientID
	})
	presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, verifiableCredential)
	dpopHeader, _, _ := newSignedTestDPoP()
	httpRequest := &http.Request{
		Header: http.Header{
			"Dpop": []string{dpopHeader.String()},
		},
	}
	contextWithValue := context.WithValue(context.Background(), httpRequestContextKey{}, httpRequest)
	clientID := "https://example.com/oauth2/holder"

	t.Run("shared code for all grant types", func(t *testing.T) {
		validatorFunc := CredentialProfile(func(_ context.Context, _ pe.WalletOwnerMapping, _ *AccessToken) error {
			return nil
		})
		t.Run("missing presentation expiry date", func(t *testing.T) {
			ctx := newTestClient(t)
			presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
				require.NoError(t, token.Remove(jwt.ExpirationKey))
			}, verifiableCredential)

			_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

			require.EqualError(t, err, "invalid_request - presentation is missing creation or expiration date")
		})
		t.Run("missing presentation not before date", func(t *testing.T) {
			ctx := newTestClient(t)
			presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
				require.NoError(t, token.Remove(jwt.NotBeforeKey))
			}, verifiableCredential)

			_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

			require.EqualError(t, err, "invalid_request - presentation is missing creation or expiration date")
		})
		t.Run("missing presentation valid for too long", func(t *testing.T) {
			ctx := newTestClient(t)
			presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
				require.NoError(t, token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
			}, verifiableCredential)

			_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

			require.EqualError(t, err, "invalid_request - presentation is valid for too long (max 5s)")
		})
		t.Run("not all VPs have the same credential subject ID", func(t *testing.T) {
			ctx := newTestClient(t)

			secondSubjectID := did.MustParseDID("did:web:example.com:other")
			secondPresentation := test.CreateJSONLDPresentation(t, secondSubjectID, proofVisitor, test.JWTNutsOrganizationCredential(t, secondSubjectID))

			_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation, secondPresentation}, validatorFunc)
			assert.EqualError(t, err, "invalid_request - not all presentations have the same credential subject ID")
		})
		t.Run("nonce", func(t *testing.T) {
			t.Run("replay attack (nonce is reused)", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.vcVerifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil).Times(2)

				_, err := ctx.client.handleBearerTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)
				require.NoError(t, err)

				_, err = ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)
				assert.EqualError(t, err, "invalid_request - presentation nonce has already been used")
			})
			t.Run("JSON-LD VP is missing nonce", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
				proofVisitor := test.LDProofVisitor(func(proof *proof.LDProof) {
					proof.Domain = &issuerClientID
					proof.Nonce = nil
				})
				presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)
				assert.EqualError(t, err, "invalid_request - presentation has invalid/missing nonce")
			})
			t.Run("JSON-LD VP has empty nonce", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
				proofVisitor := test.LDProofVisitor(func(proof *proof.LDProof) {
					proof.Domain = &issuerClientID
					proof.Nonce = new(string)
				})
				presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)
				assert.EqualError(t, err, "invalid_request - presentation has invalid/missing nonce")
			})
			t.Run("JWT VP is missing nonce", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
				presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
					_ = token.Set(jwt.AudienceKey, issuerClientID)
					_ = token.Remove("nonce")
				}, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				require.EqualError(t, err, "invalid_request - presentation has invalid/missing nonce")
			})
			t.Run("JWT VP has empty nonce", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
				presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
					_ = token.Set(jwt.AudienceKey, issuerClientID)
					_ = token.Set("nonce", "")
				}, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				require.EqualError(t, err, "invalid_request - presentation has invalid/missing nonce")
			})
			t.Run("JWT VP nonce is not a string", func(t *testing.T) {
				ctx := newTestClient(t)
				ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
				presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
					_ = token.Set(jwt.AudienceKey, issuerClientID)
					_ = token.Set("nonce", true)
				}, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				require.EqualError(t, err, "invalid_request - presentation has invalid/missing nonce")
			})
		})
		t.Run("audience", func(t *testing.T) {
			t.Run("missing", func(t *testing.T) {
				ctx := newTestClient(t)
				presentation, _ := test.CreateJWTPresentation(t, *subjectDID, nil, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				assert.EqualError(t, err, "invalid_request - expected: https://example.com/oauth2/issuer, got: [] - presentation audience/domain is missing or does not match")
			})
			t.Run("not matching", func(t *testing.T) {
				ctx := newTestClient(t)
				presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
					require.NoError(t, token.Set(jwt.AudienceKey, "did:example:other"))
				}, verifiableCredential)

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				assert.EqualError(t, err, "invalid_request - expected: https://example.com/oauth2/issuer, got: [did:example:other] - presentation audience/domain is missing or does not match")
			})
		})
		t.Run("VP verification fails", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vcVerifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(nil, errors.New("invalid"))
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)

			_, err := ctx.client.handleBearerTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

			assert.EqualError(t, err, "invalid_request - invalid - presentation(s) or credential(s) verification failed")
		})
		t.Run("proof of ownership", func(t *testing.T) {
			t.Run("VC without credentialSubject.id", func(t *testing.T) {
				ctx := newTestClient(t)
				presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, vc.VerifiableCredential{
					CredentialSubject: []map[string]any{{}},
				})

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

				assert.EqualError(t, err, `invalid_request - unable to get subject DID from VC: credential subjects have no ID`)
			})
			t.Run("signing key is not owned by credentialSubject.id", func(t *testing.T) {
				ctx := newTestClient(t)
				// Copy the proof map to avoid mutating the shared presentation used by later tests
				originalProof := presentation.Proof[0].(map[string]interface{})
				invalidProof := make(map[string]interface{})
				for k, v := range originalProof {
					invalidProof[k] = v
				}
				invalidProof["verificationMethod"] = "did:example:other#1"
				verifiablePresentation := test.ParsePresentation(t, vc.VerifiablePresentation{
					VerifiableCredential: []vc.VerifiableCredential{verifiableCredential},
					Proof:                []interface{}{invalidProof},
				})

				_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{verifiablePresentation}, validatorFunc)

				assert.EqualError(t, err, `invalid_request - presentation signer is not credential subject`)
			})
		})
		t.Run("unsupported scope", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), "everything").Return(nil, policy.ErrNotFound)

			_, err := ctx.client.handleBearerTokenRequest(context.Background(), clientID, issuerSubjectID, "everything", []VerifiablePresentation{presentation}, validatorFunc)

			assert.EqualError(t, err, `invalid_scope - not found - unsupported scope (everything) for presentation exchange: not found`)
		})
		t.Run("invalid DPoP header", func(t *testing.T) {
			ctx := newTestClient(t)
			httpRequest := &http.Request{Header: http.Header{"Dpop": []string{"invalid"}}}
			httpRequest.Header.Set("DPoP", "invalid")
			contextWithValue := context.WithValue(context.Background(), httpRequestContextKey{}, httpRequest)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)

			_, err := ctx.client.handleBearerTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScope, []VerifiablePresentation{presentation}, validatorFunc)

			_ = assertOAuthErrorWithCode(t, err, oauth.InvalidDPopProof, "DPoP header is invalid")
		})
	})
	t.Run("RFC021 vp_bearer token grant type", func(t *testing.T) {
		t.Run("JSON-LD VP", func(t *testing.T) {
			ctx := newTestClient(t)
			ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
			ctxWithRequest := context.WithValue(context.Background(), httpRequestContextKey{}, &http.Request{Header: http.Header{}})

			resp, err := ctx.client.handleS2SAccessTokenRequest(ctxWithRequest, clientID, issuerSubjectID, requestedScope, submissionJSON, presentation.Raw())

			require.NoError(t, err)
			require.IsType(t, HandleTokenRequest200JSONResponse{}, resp)
			tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
			assert.Equal(t, "Bearer", tokenResponse.TokenType)
			assert.Equal(t, requestedScope, *tokenResponse.Scope)
			assert.Equal(t, int(accessTokenValidity.Seconds()), *tokenResponse.ExpiresIn)
			assert.NotEmpty(t, tokenResponse.AccessToken)
		})
		t.Run("JWT VP", func(t *testing.T) {
			ctx := newTestClient(t)
			presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
				require.NoError(t, token.Set(jwt.AudienceKey, issuerClientID))
			}, verifiableCredential)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
			ctx.vcVerifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)

			resp, err := ctx.client.handleS2SAccessTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScope, submissionJSON, presentation.Raw())

			require.NoError(t, err)
			require.IsType(t, HandleTokenRequest200JSONResponse{}, resp)
			tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
			assert.Equal(t, "DPoP", tokenResponse.TokenType)
			assert.Equal(t, requestedScope, *tokenResponse.Scope)
			assert.Equal(t, int(accessTokenValidity.Seconds()), *tokenResponse.ExpiresIn)
			assert.NotEmpty(t, tokenResponse.AccessToken)
		})
		t.Run("VP is not valid JSON", func(t *testing.T) {
			ctx := newTestClient(t)
			resp, err := ctx.client.handleS2SAccessTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, submissionJSON, "[true, false]")

			assert.EqualError(t, err, "invalid_request - assertion parameter is invalid: unable to parse PEX envelope as verifiable presentation: invalid JWT")
			assert.Nil(t, resp)
		})
		t.Run("submission is not valid JSON", func(t *testing.T) {
			ctx := newTestClient(t)

			resp, err := ctx.client.handleS2SAccessTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, "not-a-valid-submission", presentation.Raw())

			assert.EqualError(t, err, `invalid_request - invalid presentation submission: invalid character 'o' in literal null (expecting 'u')`)
			assert.Nil(t, resp)
		})
		t.Run("re-evaluation of presentation definition yields different credentials", func(t *testing.T) {
			// This indicates the client presented credentials that don't actually match the presentation definition,
			// which could indicate a malicious client.
			otherVerifiableCredential := vc.VerifiableCredential{
				CredentialSubject: []map[string]any{
					{
						"id": subjectDID.String(),
						// just for demonstration purposes, what matters is that the credential does not match the presentation definition.
						"IsAdministrator": true,
					},
				},
			}
			presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, otherVerifiableCredential)

			ctx := newTestClient(t)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)

			resp, err := ctx.client.handleS2SAccessTokenRequest(context.Background(), clientID, issuerSubjectID, requestedScope, submissionJSON, presentation.Raw())
			assert.EqualError(t, err, "invalid_request - presentation submission does not conform to presentation definition (id=)")
			assert.Nil(t, resp)
		})
	})
	t.Run("JWT bearer token grant type", func(t *testing.T) {
		t.Run("2 scopes", func(t *testing.T) {
			ctx := newTestClient(t)
			presentation, _ := test.CreateJWTPresentation(t, *subjectDID, func(token jwt.Token) {
				require.NoError(t, token.Set(jwt.AudienceKey, issuerClientID))
			}, verifiableCredential)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope).Return(walletOwnerMapping, nil)
			ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), requestedScope2).Return(walletOwnerMapping, nil)
			ctx.vcVerifier.EXPECT().VerifyVP(presentation, true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)

			resp, err := ctx.client.handleJWTBearerTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScopes, presentation.Raw())

			require.NoError(t, err)
			require.IsType(t, HandleTokenRequest200JSONResponse{}, resp)
			tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
			assert.Equal(t, "DPoP", tokenResponse.TokenType)
			assert.Equal(t, requestedScopes, *tokenResponse.Scope)
			assert.Equal(t, int(accessTokenValidity.Seconds()), *tokenResponse.ExpiresIn)
			assert.NotEmpty(t, tokenResponse.AccessToken)
		})
		t.Run("invalid assertion parameter (not a valid VP)", func(t *testing.T) {
			ctx := newTestClient(t)

			resp, err := ctx.client.handleJWTBearerTokenRequest(contextWithValue, clientID, issuerSubjectID, requestedScope, "not-a-valid-vp")

			assert.EqualError(t, err, "invalid_request - parsing assertion as verifiable presentation: invalid JWT - assertion parameter is invalid")
			assert.Nil(t, resp)
		})
	})

}

func TestWrapper_handleJWTBearerTokenRequest(t *testing.T) {
	t.Run("2 scopes", func(t *testing.T) {

	})
}

func TestWrapper_createAccessToken(t *testing.T) {
	credentialSubjectID := did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")
	verificationMethodID := ssi.MustParseURI(credentialSubjectID.String() + "#1")
	credential, err := vc.ParseVerifiableCredential(jsonld.TestOrganizationCredential)
	require.NoError(t, err)
	presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
		VerifiableCredential: []vc.VerifiableCredential{*credential},
		Proof: []interface{}{
			proof.LDProof{
				VerificationMethod: verificationMethodID,
			},
		},
	})
	fieldId := "credential_type"
	definition := pe.PresentationDefinition{
		Id: "definitive",
		InputDescriptors: []*pe.InputDescriptor{
			{
				Id: "1",
				Constraints: &pe.Constraints{
					Fields: []pe.Field{
						{
							Path: []string{"$.type"},
							Id:   &fieldId,
							Filter: &pe.Filter{
								Type: "string",
							},
						},
					},
				},
			},
		},
	}
	submission := pe.PresentationSubmission{
		Id:           "submissive",
		DefinitionId: "definitive",
		DescriptorMap: []pe.InputDescriptorMappingObject{
			{
				Id:     "1",
				Path:   "$.verifiableCredential",
				Format: "ldp_vc",
			},
		},
	}
	dpopToken, _, _ := newSignedTestDPoP()
	expectedPresentations := []vc.VerifiablePresentation{test.ParsePresentation(t, presentation)}
	expectedSubmissions := map[string]pe.PresentationSubmission{
		"definitive": submission,
	}
	expectedPresentationDefinitions := map[pe.WalletOwnerType]pe.PresentationDefinition{
		pe.WalletOwnerOrganization: definition,
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		require.NoError(t, err)
		accessToken, err := ctx.client.createAccessToken(issuerURL.String(), credentialSubjectID.String(), time.Now(), "everything", AccessToken{
			PresentationSubmissions: expectedSubmissions,
			PresentationDefinitions: expectedPresentationDefinitions,
			VPToken:                 expectedPresentations,
			InputDescriptorConstraintIdMap: map[string]any{
				"credential_type": []interface{}{"NutsOrganizationCredential", "VerifiableCredential"},
			},
		}, dpopToken)

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken.AccessToken)
		assert.Equal(t, "DPoP", accessToken.TokenType)
		assert.Equal(t, 900, *accessToken.ExpiresIn)
		assert.Equal(t, "everything", *accessToken.Scope)

		var storedToken AccessToken
		err = ctx.client.accessTokenServerStore().Get(accessToken.AccessToken, &storedToken)
		require.NoError(t, err)
		assert.Equal(t, accessToken.AccessToken, storedToken.Token)
		assert.Equal(t, submission, storedToken.PresentationSubmissions["definitive"])
		assert.Equal(t, definition, storedToken.PresentationDefinitions[pe.WalletOwnerOrganization])
		assert.Equal(t, []interface{}{"NutsOrganizationCredential", "VerifiableCredential"}, storedToken.InputDescriptorConstraintIdMap["credential_type"])
		expectedVPJSON, _ := presentation.MarshalJSON()
		actualVPJSON, _ := storedToken.VPToken[0].MarshalJSON()
		assert.JSONEq(t, string(expectedVPJSON), string(actualVPJSON))
		assert.Equal(t, issuerURL.String(), storedToken.Issuer)
		assert.NotEmpty(t, storedToken.Expiration)
	})
	t.Run("ok - bearer token", func(t *testing.T) {
		ctx := newTestClient(t)
		accessToken, err := ctx.client.createAccessToken(issuerURL.String(), credentialSubjectID.String(), time.Now(), "everything", AccessToken{}, nil)

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken.AccessToken)
		assert.Equal(t, "Bearer", accessToken.TokenType)
	})
}
