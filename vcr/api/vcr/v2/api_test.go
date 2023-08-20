/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_IssueVC(t *testing.T) {

	issuerURI := ssi.MustParseURI("did:nuts:123")
	credentialType := ssi.MustParseURI("ExampleType")

	expectedRequestedVC := vc.VerifiableCredential{
		Context:           []ssi.URI{credential.NutsV1ContextURI},
		Type:              []ssi.URI{credentialType},
		Issuer:            issuerURI,
		CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
	}

	t.Run("ok with an actual credential", func(t *testing.T) {
		testContext := newMockContext(t)

		public := Public
		request := IssueVCRequest{
			Type:              expectedRequestedVC.Type[0].String(),
			Issuer:            expectedRequestedVC.Issuer.String(),
			CredentialSubject: expectedRequestedVC.CredentialSubject,
			Visibility:        &public,
		}
		// assert that credential.NutsV1ContextURI is added if the request does not contain @context
		testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Eq(expectedRequestedVC), true, true).Return(&expectedRequestedVC, nil)

		response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, IssueVC200JSONResponse(expectedRequestedVC), response)
	})

	t.Run("checking request params", func(t *testing.T) {

		t.Run("err - missing credential type", func(t *testing.T) {
			testContext := newMockContext(t)

			public := Public
			request := IssueVCRequest{
				//Type:              expectedRequestedVC.Type[0].String(),
				Issuer:            expectedRequestedVC.Issuer.String(),
				CredentialSubject: expectedRequestedVC.CredentialSubject,
				Visibility:        &public,
			}

			response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

			assert.EqualError(t, err, "missing credential type")
			assert.Empty(t, response)
		})

		t.Run("err - missing credentialSubject", func(t *testing.T) {
			testContext := newMockContext(t)

			public := Public
			request := IssueVCRequest{
				Type:   expectedRequestedVC.Type[0].String(),
				Issuer: expectedRequestedVC.Issuer.String(),
				//CredentialSubject: expectedRequestedVC.CredentialSubject,
				Visibility: &public,
			}

			response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

			assert.EqualError(t, err, "missing credentialSubject")
			assert.Empty(t, response)
		})
	})

	t.Run("test params", func(t *testing.T) {
		t.Run("publish is true", func(t *testing.T) {

			t.Run("ok - visibility private", func(t *testing.T) {
				testContext := newMockContext(t)

				publishValue := true
				visibilityValue := Private
				request := IssueVCRequest{
					Type:              expectedRequestedVC.Type[0].String(),
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Visibility:        &visibilityValue,
					PublishToNetwork:  &publishValue,
				}
				expectedVC := vc.VerifiableCredential{}
				expectedResponse := IssueVC200JSONResponse(expectedVC)
				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), true, false).Return(&expectedVC, nil)

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.NoError(t, err)
				assert.Equal(t, expectedResponse, response)
			})

			t.Run("ok - visibility public", func(t *testing.T) {
				testContext := newMockContext(t)

				publishValue := true
				visibilityValue := Public
				request := IssueVCRequest{
					Type:              expectedRequestedVC.Type[0].String(),
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Visibility:        &visibilityValue,
					PublishToNetwork:  &publishValue,
				}
				expectedVC := vc.VerifiableCredential{}
				expectedResponse := IssueVC200JSONResponse(expectedVC)
				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), true, true).Return(&expectedVC, nil)

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.NoError(t, err)
				assert.Equal(t, expectedResponse, response)
			})

			t.Run("err - visibility not set", func(t *testing.T) {
				testContext := newMockContext(t)

				publishValue := true
				visibilityValue := IssueVCRequestVisibility("")
				request := IssueVCRequest{
					Visibility:       &visibilityValue,
					PublishToNetwork: &publishValue,
				}

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.Empty(t, response)
				assert.EqualError(t, err, "visibility must be set when publishing credential")
			})

			t.Run("err - visibility contains invalid value", func(t *testing.T) {
				testContext := newMockContext(t)

				publishValue := true
				visibilityValue := IssueVCRequestVisibility("only when it rains")
				request := IssueVCRequest{
					Visibility:       &visibilityValue,
					PublishToNetwork: &publishValue,
				}

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.Empty(t, response)
				assert.EqualError(t, err, "invalid value for visibility")
			})

		})

		t.Run("err - publish false and visibility is set", func(t *testing.T) {
			testContext := newMockContext(t)

			publishValue := false
			visibilityValue := Private
			request := IssueVCRequest{
				Visibility:       &visibilityValue,
				PublishToNetwork: &publishValue,
			}

			response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

			assert.Empty(t, response)
			assert.EqualError(t, err, "visibility setting is only allowed when publishing to the network")
		})

		t.Run("publish is false", func(t *testing.T) {
			testContext := newMockContext(t)

			publishValue := false
			request := IssueVCRequest{
				Type:              expectedRequestedVC.Type[0].String(),
				CredentialSubject: expectedRequestedVC.CredentialSubject,
				PublishToNetwork:  &publishValue,
			}
			expectedVC := vc.VerifiableCredential{}
			expectedResponse := IssueVC200JSONResponse(expectedVC)
			testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), false, false).Return(&expectedVC, nil)

			response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

			assert.NoError(t, err)
			assert.Equal(t, expectedResponse, response)
		})
	})

	t.Run("test errors", func(t *testing.T) {
		public := Public
		validIssueRequest := IssueVCRequest{
			Type:              expectedRequestedVC.Type[0].String(),
			CredentialSubject: expectedRequestedVC.CredentialSubject,
			Visibility:        &public,
		}

		tests := []struct {
			name       string
			err        error
			statusCode int
		}{
			{
				name:       "issue returns random error",
				err:        errors.New("could not issue"),
				statusCode: 0,
			},
			{
				name:       "missing service",
				err:        fmt.Errorf("nested error for: %w", types.ErrServiceNotFound),
				statusCode: http.StatusPreconditionFailed,
			},
			{
				name:       "did not found",
				err:        fmt.Errorf("nested error for: %w", types.ErrNotFound),
				statusCode: http.StatusBadRequest,
			},
			{
				name:       "key not found",
				err:        fmt.Errorf("nested error for: %w", types.ErrKeyNotFound),
				statusCode: http.StatusBadRequest,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, test.err)

				_, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &validIssueRequest})

				assert.Equal(t, test.statusCode, testContext.client.ResolveStatusCode(err))
			})
		}
	})
}

func TestWrapper_SearchIssuedVCs(t *testing.T) {
	subjectID := ssi.MustParseURI("did:nuts:456")
	issuerDID, _ := did.ParseDID("did:nuts:123")
	issuerID := ssi.MustParseURI(issuerDID.String())
	vcID := issuerID
	vcID.Fragment = "1"
	subjectIDString := subjectID.String()
	testCredential := ssi.MustParseURI("TestCredential")

	foundVC := vc.VerifiableCredential{
		ID:                &vcID,
		Type:              []ssi.URI{testCredential},
		Issuer:            issuerID,
		CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
	}

	t.Run("ok - with subject, no results", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, &subjectID)
		expectedResponse := SearchIssuedVCs200JSONResponse(SearchVCResults{VerifiableCredentials: []SearchVCResult{}})
		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
			Subject:        &subjectIDString,
		}

		response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("ok - without subject, 1 result", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return([]VerifiableCredential{foundVC}, nil)
		testContext.mockVerifier.EXPECT().GetRevocation(vcID).Return(nil, verifier.ErrNotFound)
		expectedResponse := SearchIssuedVCs200JSONResponse(SearchVCResults{VerifiableCredentials: []SearchVCResult{{VerifiableCredential: foundVC}}})
		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}

		response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("ok - without subject, 1 result, revoked", func(t *testing.T) {
		revocation := &Revocation{Reason: "because of reasons"}
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return([]VerifiableCredential{foundVC}, nil)
		testContext.mockVerifier.EXPECT().GetRevocation(vcID).Return(revocation, nil)
		expectedResponse := SearchIssuedVCs200JSONResponse(SearchVCResults{VerifiableCredentials: []SearchVCResult{{VerifiableCredential: foundVC, Revocation: revocation}}})
		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}

		response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("error - invalid input", func(t *testing.T) {

		t.Run("invalid issuer", func(t *testing.T) {
			testContext := newMockContext(t)
			params := SearchIssuedVCsParams{
				CredentialType: "TestCredential",
				Issuer:         "abc",
				Subject:        &subjectIDString,
			}

			response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

			assert.EqualError(t, err, "invalid issuer did: invalid DID: input length is less than 7")
			assert.Empty(t, response)
		})

		t.Run("invalid subject", func(t *testing.T) {
			testContext := newMockContext(t)
			invalidSubjectStr := "%%"
			params := SearchIssuedVCsParams{
				CredentialType: "TestCredential",
				Issuer:         issuerID.String(),
				Subject:        &invalidSubjectStr,
			}
			response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

			assert.EqualError(t, err, "invalid subject id: parse \"%%\": invalid URL escape \"%%\"")
			assert.Empty(t, response)
		})

		t.Run("invalid credentialType", func(t *testing.T) {
			testContext := newMockContext(t)
			params := SearchIssuedVCsParams{
				CredentialType: "%%",
				Issuer:         issuerID.String(),
				Subject:        &subjectIDString,
			}

			response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

			assert.EqualError(t, err, "invalid credentialType: parse \"%%\": invalid URL escape \"%%\"")
			assert.Empty(t, response)
		})
	})

	t.Run("error - CredentialResolver returns error", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return(nil, errors.New("b00m!"))
		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}

		response, err := testContext.client.SearchIssuedVCs(testContext.requestCtx, SearchIssuedVCsRequestObject{Params: params})

		assert.EqualError(t, err, "b00m!")
		assert.Empty(t, response)
	})
}

func TestWrapper_VerifyVC(t *testing.T) {
	issuerURI := ssi.MustParseURI("did:nuts:123")
	credentialType := ssi.MustParseURI("ExampleType")

	allowUntrusted := true
	options := VCVerificationOptions{
		AllowUntrustedIssuer: &allowUntrusted,
	}

	expectedVC := vc.VerifiableCredential{
		Type:              []ssi.URI{credentialType},
		Issuer:            issuerURI,
		CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
	}

	expectedVerifyRequest := VCVerificationRequest{
		VerifiableCredential: expectedVC,
		VerificationOptions:  &options,
	}

	t.Run("valid vc", func(t *testing.T) {
		testContext := newMockContext(t)
		expectedResponse := VerifyVC200JSONResponse(VCVerificationResult{Validity: true})

		testContext.mockVerifier.EXPECT().Verify(expectedVC, allowUntrusted, true, nil)

		response, err := testContext.client.VerifyVC(testContext.requestCtx, VerifyVCRequestObject{Body: &expectedVerifyRequest})
		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("invalid vc", func(t *testing.T) {
		testContext := newMockContext(t)
		message := "invalid vc"
		expectedResponse := VerifyVC200JSONResponse(VCVerificationResult{Validity: false, Message: &message})

		testContext.mockVerifier.EXPECT().Verify(expectedVC, true, true, nil).Return(errors.New(message))

		response, err := testContext.client.VerifyVC(testContext.requestCtx, VerifyVCRequestObject{Body: &expectedVerifyRequest})
		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
}

func TestWrapper_RevokeVC(t *testing.T) {
	credentialID := "did:nuts:123#abc"
	credentialURI := ssi.MustParseURI(credentialID)

	t.Run("test integration with vcr", func(t *testing.T) {
		t.Run("successful revocation", func(t *testing.T) {
			testContext := newMockContext(t)
			expectedRevocation := &Revocation{Subject: credentialURI}
			testContext.mockIssuer.EXPECT().Revoke(gomock.Any(), credentialURI).Return(expectedRevocation, nil)
			expectedResponse := RevokeVC200JSONResponse(*expectedRevocation)

			response, err := testContext.client.RevokeVC(testContext.requestCtx, RevokeVCRequestObject{Id: credentialID})

			assert.NoError(t, err)
			assert.Equal(t, expectedResponse, response)
		})

		t.Run("vcr returns an error", func(t *testing.T) {
			testContext := newMockContext(t)
			testContext.mockIssuer.EXPECT().Revoke(gomock.Any(), credentialURI).Return(nil, errors.New("credential not found"))

			response, err := testContext.client.RevokeVC(testContext.requestCtx, RevokeVCRequestObject{Id: credentialID})

			assert.Empty(t, response)
			assert.EqualError(t, err, "credential not found")
		})
	})

	t.Run("param check", func(t *testing.T) {
		t.Run("invalid credential id format", func(t *testing.T) {
			testContext := newMockContext(t)

			response, err := testContext.client.RevokeVC(testContext.requestCtx, RevokeVCRequestObject{Id: "%%"})

			assert.Empty(t, response)
			assert.EqualError(t, err, "invalid credential id: parse \"%%\": invalid URL escape \"%%\"")
		})

	})
}

// parsedTimeStr returns the original (truncated) time and an RFC3339 string with an extra round of formatting/parsing
func parsedTimeStr(t time.Time) (time.Time, string) {
	formatted := t.Format(time.RFC3339)
	parsed, _ := time.Parse(time.RFC3339, formatted)
	formatted = parsed.Format(time.RFC3339)
	return parsed, formatted
}

func TestWrapper_CreateVP(t *testing.T) {
	issuerURI := ssi.MustParseURI("did:nuts:123")
	credentialType := ssi.MustParseURI("ExampleType")

	subjectDID := did.MustParseDID("did:nuts:456")
	subjectDIDString := subjectDID.String()
	verifiableCredential := vc.VerifiableCredential{
		Type:              []ssi.URI{credentialType},
		Issuer:            issuerURI,
		CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID.String()}},
	}
	result := &vc.VerifiablePresentation{}
	expectedresponse := CreateVP200JSONResponse(*result)

	createRequest := func() CreateVPRequest {
		return CreateVPRequest{VerifiableCredentials: []VerifiableCredential{verifiableCredential}}
	}

	created := time.Now()
	clockFn = func() time.Time {
		return created
	}
	t.Cleanup(func() {
		clockFn = time.Now
	})

	t.Run("ok - without signer DID", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		testContext.mockHolder.EXPECT().BuildVP(
			testContext.requestCtx,
			[]VerifiableCredential{verifiableCredential},
			holder.PresentationOptions{ProofOptions: proof.ProofOptions{Created: created}},
			nil,
			true,
		).Return(result, nil)

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Equal(t, expectedresponse, response)
		assert.NoError(t, err)
	})
	t.Run("ok - with signer DID", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		request.SignerDID = &subjectDIDString
		testContext.mockHolder.EXPECT().BuildVP(
			testContext.requestCtx,
			[]VerifiableCredential{verifiableCredential},
			holder.PresentationOptions{ProofOptions: proof.ProofOptions{Created: created}},
			&subjectDID,
			true,
		).Return(result, nil)

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Equal(t, expectedresponse, response)
		assert.NoError(t, err)
	})
	t.Run("ok - with options", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		expired, expiredStr := parsedTimeStr(created.Add(time.Hour))
		proofPurpose := "authentication"
		ldContext := credential.NutsV1ContextURI
		vpType := ssi.MustParseURI("SpecialPresentation")
		request.Expires = &expiredStr
		purpose := CreateVPRequestProofPurpose(proofPurpose)
		request.ProofPurpose = &purpose
		request.Context = &[]string{ldContext.String()}
		request.Type = &[]string{vpType.String()}
		opts := holder.PresentationOptions{
			AdditionalContexts: []ssi.URI{ldContext},
			AdditionalTypes:    []ssi.URI{vpType},
			ProofOptions: proof.ProofOptions{
				Created:      created,
				Expires:      &expired,
				ProofPurpose: proofPurpose,
			},
		}
		testContext.mockHolder.EXPECT().BuildVP(
			testContext.requestCtx,
			[]VerifiableCredential{verifiableCredential},
			opts,
			nil,
			true,
		).Return(result, nil)

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Equal(t, expectedresponse, response)
		assert.NoError(t, err)
	})
	t.Run("error - with expires, but in the past", func(t *testing.T) {
		testContext := newMockContext(t)
		expired := time.Time{}
		request := createRequest()
		expiredStr := expired.Format(time.RFC3339)
		request.Expires = &expiredStr

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "expires can not lay in the past")
	})
	t.Run("error - invalid expires format", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		expiredStr := "a"
		request.Expires = &expiredStr

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.Contains(t, err.Error(), "invalid value for expires")
	})
	t.Run("error - no VCs", func(t *testing.T) {
		testContext := newMockContext(t)
		request := CreateVPRequest{}

		response, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "verifiableCredentials needs at least 1 item")
	})
	t.Run("error - invalid context", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		request.Context = &[]string{":"}

		_, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		require.Error(t, err)
		assert.EqualError(t, err, "invalid value for context: parse \":\": missing protocol scheme")
	})
	t.Run("error - invalid type", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		request.Type = &[]string{":"}

		_, err := testContext.client.CreateVP(testContext.requestCtx, CreateVPRequestObject{Body: &request})

		require.Error(t, err)
		assert.EqualError(t, err, "invalid value for type: parse \":\": missing protocol scheme")
	})
}

func TestWrapper_VerifyVP(t *testing.T) {
	verifiableCredential := vc.VerifiableCredential{
		Type: []ssi.URI{ssi.MustParseURI("ExampleType")},
	}
	vp := vc.VerifiablePresentation{
		VerifiableCredential: []VerifiableCredential{verifiableCredential},
		Proof:                []interface{}{"It's a very good proof. I know it because I made it myself. ALl the rest is fake."},
	}
	expectedVCs := []VerifiableCredential{vp.VerifiableCredential[0]}

	t.Run("ok", func(t *testing.T) {
		testContext := newMockContext(t)
		validAt, validAtStr := parsedTimeStr(time.Now())
		request := VPVerificationRequest{
			VerifiablePresentation: vp,
			ValidAt:                &validAtStr,
		}
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, false, &validAt).Return(vp.VerifiableCredential, nil)
		expectedResponse := VerifyVP200JSONResponse(VPVerificationResult{
			Credentials: &expectedVCs,
			Validity:    true,
		})

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("ok - verifyCredentials set", func(t *testing.T) {
		testContext := newMockContext(t)
		verifyCredentials := false
		request := VPVerificationRequest{VerifiablePresentation: vp, VerifyCredentials: &verifyCredentials}
		testContext.mockVerifier.EXPECT().VerifyVP(vp, false, false, nil).Return(vp.VerifiableCredential, nil)
		expectedResponse := VerifyVP200JSONResponse(VPVerificationResult{
			Credentials: &expectedVCs,
			Validity:    true,
		})

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("error - verification failed (other error)", func(t *testing.T) {
		testContext := newMockContext(t)
		request := VPVerificationRequest{VerifiablePresentation: vp}
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, false, nil).Return(nil, errors.New("failed"))

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.Error(t, err)
		assert.Empty(t, response)
	})
	t.Run("error - invalid validAt format", func(t *testing.T) {
		testContext := newMockContext(t)
		validAtStr := "a"
		request := VPVerificationRequest{
			VerifiablePresentation: vp,
			ValidAt:                &validAtStr,
		}

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.Contains(t, err.Error(), "invalid value for validAt")
	})
	t.Run("error - verification failed (verification error)", func(t *testing.T) {
		testContext := newMockContext(t)
		request := VPVerificationRequest{VerifiablePresentation: vp}
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, false, nil).Return(nil, verifier.VerificationError{})
		errMsg := "verification error: "
		expectedRepsonse := VerifyVP200JSONResponse(VPVerificationResult{
			Message:  &errMsg,
			Validity: false,
		})

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.Equal(t, expectedRepsonse, response)
		assert.NoError(t, err)
	})
}

func TestWrapper_TrustUntrust(t *testing.T) {
	vc := vc.VerifiableCredential{}
	json.Unmarshal([]byte(jsonld.TestCredential), &vc)
	issuer := vc.Issuer
	cType := vc.Type[0]

	t.Run("ok - add", func(t *testing.T) {
		ctx := newMockContext(t)
		request := CredentialIssuer{
			CredentialType: cType.String(),
			Issuer:         issuer.String(),
		}
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(nil)

		response, err := ctx.client.TrustIssuer(ctx.requestCtx, TrustIssuerRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, TrustIssuer204Response{}, response)
	})

	t.Run("ok - remove", func(t *testing.T) {
		ctx := newMockContext(t)
		request := CredentialIssuer{
			CredentialType: cType.String(),
			Issuer:         issuer.String(),
		}
		ctx.vcr.EXPECT().Untrust(cType, issuer).Return(nil)

		response, err := ctx.client.UntrustIssuer(ctx.requestCtx, UntrustIssuerRequestObject{Body: &request})

		require.NoError(t, err)
		assert.Equal(t, UntrustIssuer204Response{}, response)
	})

	t.Run("error - invalid issuer", func(t *testing.T) {
		ctx := newMockContext(t)
		request := CredentialIssuer{
			CredentialType: cType.String(),
			Issuer:         string([]byte{0}),
		}

		response, err := ctx.client.TrustIssuer(ctx.requestCtx, TrustIssuerRequestObject{Body: &request})

		assert.EqualError(t, err, "failed to parse issuer: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Empty(t, response)
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		request := CredentialIssuer{
			Issuer:         cType.String(),
			CredentialType: string([]byte{0}),
		}

		response, err := ctx.client.TrustIssuer(ctx.requestCtx, TrustIssuerRequestObject{Body: &request})

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Empty(t, response)
	})

	t.Run("error - failed to add", func(t *testing.T) {
		ctx := newMockContext(t)

		request := CredentialIssuer{
			CredentialType: cType.String(),
			Issuer:         issuer.String(),
		}
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(errors.New("b00m!"))

		response, err := ctx.client.TrustIssuer(ctx.requestCtx, TrustIssuerRequestObject{Body: &request})

		assert.Error(t, err)
		assert.Empty(t, response)
	})
}

func TestWrapper_Trusted(t *testing.T) {
	credentialType := ssi.MustParseURI("did:nuts:abc")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Trusted(credentialType).Return([]ssi.URI{credentialType}, nil)
		expectedResponse := ListTrusted200JSONResponse([]string{credentialType.String()})

		response, err := ctx.client.ListTrusted(ctx.requestCtx, ListTrustedRequestObject{CredentialType: credentialType.String()})

		require.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.ListTrusted(ctx.requestCtx, ListTrustedRequestObject{CredentialType: string([]byte{0})})

		assert.Error(t, err)
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Empty(t, response)
	})
}

func TestWrapper_Untrusted(t *testing.T) {
	credentialType := ssi.MustParseURI("did:nuts:abc")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Untrusted(credentialType).Return([]ssi.URI{credentialType}, nil)
		expectedResponse := ListUntrusted200JSONResponse([]string{credentialType.String()})

		response, err := ctx.client.ListUntrusted(ctx.requestCtx, ListUntrustedRequestObject{CredentialType: credentialType.String()})

		require.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("error - malformed input", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.ListUntrusted(ctx.requestCtx, ListUntrustedRequestObject{CredentialType: string([]byte{0})})

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Empty(t, response)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Untrusted(credentialType).Return(nil, errors.New("b00m!"))

		response, err := ctx.client.ListUntrusted(ctx.requestCtx, ListUntrustedRequestObject{CredentialType: credentialType.String()})

		assert.EqualError(t, err, "b00m!")
		assert.Empty(t, response)
	})
}

type mockContext struct {
	ctrl         *gomock.Controller
	mockIssuer   *issuer.MockIssuer
	mockHolder   *holder.MockHolder
	mockVerifier *verifier.MockVerifier
	vcr          *vcr.MockVCR
	client       *Wrapper
	requestCtx   context.Context
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockVcr := vcr.NewMockVCR(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	mockHolder := holder.NewMockHolder(ctrl)
	mockVerifier := verifier.NewMockVerifier(ctrl)
	mockVcr.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	mockVcr.EXPECT().Holder().Return(mockHolder).AnyTimes()
	mockVcr.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
	client := &Wrapper{VCR: mockVcr, ContextManager: jsonld.NewTestJSONLDManager(t)}

	requestCtx := audit.TestContext()

	return mockContext{
		ctrl:         ctrl,
		mockIssuer:   mockIssuer,
		mockHolder:   mockHolder,
		mockVerifier: mockVerifier,
		vcr:          mockVcr,
		client:       client,
		requestCtx:   requestCtx,
	}
}
