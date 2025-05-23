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
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"net/http"
	"net/http/httptest"
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
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var holderDID = did.MustParseDID("did:web:example.com:iam:123")
var credentialID = ssi.MustParseURI("did:web:example.com:iam:456#1")
var testVC = vc.VerifiableCredential{ID: &credentialID, CredentialSubject: []map[string]any{{"id": holderDID.String()}}}

func TestWrapper_IssueVC(t *testing.T) {

	issuerURI := ssi.MustParseURI("did:nuts:123")
	credentialType := ssi.MustParseURI("ExampleType")

	expectedRequestedVC := vc.VerifiableCredential{
		Context:           []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
		Type:              []ssi.URI{credentialType},
		Issuer:            issuerURI,
		CredentialSubject: []map[string]any{{"id": "did:nuts:456"}},
	}

	t.Run("ok with an actual credential - minimal", func(t *testing.T) {
		testContext := newMockContext(t)

		public := Public
		request := IssueVCRequest{
			Issuer:            expectedRequestedVC.Issuer.String(),
			CredentialSubject: expectedRequestedVC.CredentialSubject,
			Visibility:        &public,
		}
		_ = request.Type.FromIssueVCRequestType1([]string{credentialType.String()})
		// assert that credential.NutsV1ContextURI is added if the request does not contain @context
		testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, expectedRequestedVC, issuer.CredentialOptions{
			Publish: true,
			Public:  true,
		}).Return(&expectedRequestedVC, nil)

		response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, IssueVC200JSONResponse(expectedRequestedVC), response)
	})

	t.Run("ok with an actual credential - all", func(t *testing.T) {
		testContext := newMockContext(t)
		expectedRequestedVC := expectedRequestedVC
		expectedRequestedVC.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI(), credentialType}

		public := Public
		request := IssueVCRequest{
			Context:           new(IssueVCRequest_Context),
			Issuer:            expectedRequestedVC.Issuer.String(),
			CredentialSubject: expectedRequestedVC.CredentialSubject,
			Visibility:        &public,
		}
		require.NoError(t, request.Context.FromIssueVCRequestContext1([]string{vc.VCContextV1, credential.NutsV1ContextURI.String()}))
		require.NoError(t, request.Type.FromIssueVCRequestType1([]string{vc.VerifiableCredentialType, credentialType.String()}))
		testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, expectedRequestedVC, issuer.CredentialOptions{
			Publish: true,
			Public:  true,
		}).Return(&expectedRequestedVC, nil)

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
				//Type:       expectedRequestedVC.Type[0].String(),
				Issuer:     expectedRequestedVC.Issuer.String(),
				Visibility: &public,
			}
			_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

			response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

			assert.EqualError(t, err, "missing credentialSubject")
			assert.Empty(t, response)
		})
	})

	t.Run("CredentialOptions", func(t *testing.T) {
		t.Run("did:jwk", func(t *testing.T) {
			t.Run("err - unsupported did method", func(t *testing.T) {
				testContext := newMockContext(t)

				request := IssueVCRequest{
					Issuer: "did:jwk:123",
					//Type:              "SomeCredential",
					CredentialSubject: expectedRequestedVC.CredentialSubject,
				}
				_ = request.Type.FromIssueVCRequestType0("SomeCredential")

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.EqualError(t, err, "unsupported DID method: jwk")
				assert.Nil(t, response)
			})
		})
		t.Run("did:nuts", func(t *testing.T) {
			t.Run("publish is true", func(t *testing.T) {

				t.Run("ok - visibility private", func(t *testing.T) {
					testContext := newMockContext(t)

					publishValue := true
					visibilityValue := Private
					request := IssueVCRequest{
						Issuer: expectedRequestedVC.Issuer.String(),
						//Type:              expectedRequestedVC.Type[0].String(),
						CredentialSubject: expectedRequestedVC.CredentialSubject,
						Visibility:        &visibilityValue,
						PublishToNetwork:  &publishValue,
					}
					_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())
					expectedVC := vc.VerifiableCredential{}
					expectedResponse := IssueVC200JSONResponse(expectedVC)
					testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), issuer.CredentialOptions{
						Publish: true,
						Public:  false,
					}).Return(&expectedVC, nil)

					response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

					assert.NoError(t, err)
					assert.Equal(t, expectedResponse, response)
				})

				t.Run("ok - visibility public", func(t *testing.T) {
					testContext := newMockContext(t)

					publishValue := true
					visibilityValue := Public
					request := IssueVCRequest{
						Issuer: expectedRequestedVC.Issuer.String(),
						//Type:              expectedRequestedVC.Type[0].String(),
						CredentialSubject: expectedRequestedVC.CredentialSubject,
						Visibility:        &visibilityValue,
						PublishToNetwork:  &publishValue,
					}
					_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())
					expectedVC := vc.VerifiableCredential{}
					expectedResponse := IssueVC200JSONResponse(expectedVC)
					testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), issuer.CredentialOptions{
						Publish: true,
						Public:  true,
					}).Return(&expectedVC, nil)

					response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

					assert.NoError(t, err)
					assert.Equal(t, expectedResponse, response)
				})

				t.Run("err - visibility not set", func(t *testing.T) {
					testContext := newMockContext(t)

					publishValue := true
					visibilityValue := IssueVCRequestVisibility("")
					request := IssueVCRequest{
						Issuer:           expectedRequestedVC.Issuer.String(),
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
						Issuer:           expectedRequestedVC.Issuer.String(),
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
					Issuer:           expectedRequestedVC.Issuer.String(),
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
					Issuer: expectedRequestedVC.Issuer.String(),
					//Type:              expectedRequestedVC.Type[0].String(),
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					PublishToNetwork:  &publishValue,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())
				expectedVC := vc.VerifiableCredential{}
				expectedResponse := IssueVC200JSONResponse(expectedVC)
				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), issuer.CredentialOptions{
					Publish: false,
					Public:  false,
				}).Return(&expectedVC, nil)

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.NoError(t, err)
				assert.Equal(t, expectedResponse, response)
			})
			t.Run("err - WithStatusList2021Revocation provided", func(t *testing.T) {
				testContext := newMockContext(t)

				publishValue := false
				request := IssueVCRequest{
					Issuer: expectedRequestedVC.Issuer.String(),
					//Type:                         expectedRequestedVC.Type[0].String(),
					CredentialSubject:            expectedRequestedVC.CredentialSubject,
					PublishToNetwork:             &publishValue,
					WithStatusList2021Revocation: &publishValue,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.EqualError(t, err, "illegal option 'withStatusList2021Revocation' requested for issuer's DID method: nuts")
				assert.Nil(t, response)
			})

		})
		t.Run("did:web", func(t *testing.T) {
			expectedRequestedVC := vc.VerifiableCredential{
				Context:           []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
				Type:              []ssi.URI{credentialType},
				Issuer:            ssi.MustParseURI("did:web:example.com:iam:123"),
				CredentialSubject: []map[string]any{{"id": "did:web:example.com:iam:456"}},
			}

			t.Run("ok with statuslist", func(t *testing.T) {
				testContext := newMockContext(t)
				withRevocation := true
				request := IssueVCRequest{
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Issuer:            expectedRequestedVC.Issuer.String(),
					//Type:                         expectedRequestedVC.Type[0].String(),
					WithStatusList2021Revocation: &withRevocation,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())
				// assert that credential.NutsV1ContextURI is added if the request does not contain @context
				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, expectedRequestedVC, issuer.CredentialOptions{
					WithStatusListRevocation: true,
				}).Return(&expectedRequestedVC, nil)

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.NoError(t, err)
				assert.Equal(t, IssueVC200JSONResponse(expectedRequestedVC), response)
			})
			t.Run("ok - without WithStatusList2021Revocation, with ExpirationDate", func(t *testing.T) {
				testContext := newMockContext(t)

				now := time.Now().Truncate(time.Second)
				expectedRequestedVC := vc.VerifiableCredential{
					Context:           []ssi.URI{credential.NutsV1ContextURI},
					Type:              []ssi.URI{credentialType},
					Issuer:            ssi.MustParseURI("did:web:example.com:iam:123"),
					ExpirationDate:    &now,
					CredentialSubject: []map[string]any{{"id": "did:web:example.com:iam:456"}},
				}

				nowStr := now.Format(time.RFC3339)
				request := IssueVCRequest{
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Issuer:            expectedRequestedVC.Issuer.String(),
					//Type:              expectedRequestedVC.Type[0].String(),
					ExpirationDate: &nowStr,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())
				// Circle CI keeps failing on mock comparison of expectedRequestedVC (probably .ExpirationDate) without showing any differences.
				// Since local tests succeed, and test is about checking CredentialOptions, testing value of expectedRequestedVCs is skipped.
				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), issuer.CredentialOptions{}).Return(&expectedRequestedVC, nil)

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.NoError(t, err)
				assert.Equal(t, IssueVC200JSONResponse(expectedRequestedVC), response)
			})
			t.Run("err - without WithStatusList2021Revocation and ExpirationDate", func(t *testing.T) {
				testContext := newMockContext(t)

				request := IssueVCRequest{
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Issuer:            expectedRequestedVC.Issuer.String(),
					//Type:              expectedRequestedVC.Type[0].String(),
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.EqualError(t, err, "withStatusList2021Revocation MUST be provided for credentials without expirationDate")
				assert.Nil(t, response)
			})
			t.Run("err - illegal param: publishToNetwork", func(t *testing.T) {
				testContext := newMockContext(t)

				revocation := true
				publish := false
				request := IssueVCRequest{
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Issuer:            expectedRequestedVC.Issuer.String(),
					//Type:                         expectedRequestedVC.Type[0].String(),
					WithStatusList2021Revocation: &revocation,
					PublishToNetwork:             &publish,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.EqualError(t, err, "illegal option 'publishToNetwork' requested for issuer's DID method: web")
				assert.Nil(t, response)
			})
			t.Run("err - illegal param: visibility", func(t *testing.T) {
				testContext := newMockContext(t)

				revocation := false
				visibility := Private
				request := IssueVCRequest{
					CredentialSubject: expectedRequestedVC.CredentialSubject,
					Issuer:            expectedRequestedVC.Issuer.String(),
					//Type:                         expectedRequestedVC.Type[0].String(),
					WithStatusList2021Revocation: &revocation,
					Visibility:                   &visibility,
				}
				_ = request.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

				response, err := testContext.client.IssueVC(testContext.requestCtx, IssueVCRequestObject{Body: &request})

				assert.EqualError(t, err, "illegal option 'visibility' requested for issuer's DID method: web")
				assert.Nil(t, response)
			})
		})

	})

	t.Run("test errors", func(t *testing.T) {
		public := Public
		validIssueRequest := IssueVCRequest{
			Issuer: expectedRequestedVC.Issuer.String(),
			//Type:              expectedRequestedVC.Type[0].String(),
			CredentialSubject: expectedRequestedVC.CredentialSubject,
			Visibility:        &public,
		}
		_ = validIssueRequest.Type.FromIssueVCRequestType0(expectedRequestedVC.Type[0].String())

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
				err:        fmt.Errorf("nested error for: %w", resolver.ErrServiceNotFound),
				statusCode: http.StatusPreconditionFailed,
			},
			{
				name:       "did not found",
				err:        fmt.Errorf("nested error for: %w", resolver.ErrNotFound),
				statusCode: http.StatusBadRequest,
			},
			{
				name:       "key not found",
				err:        fmt.Errorf("nested error for: %w", resolver.ErrKeyNotFound),
				statusCode: http.StatusBadRequest,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.mockIssuer.EXPECT().Issue(testContext.requestCtx, gomock.Any(), gomock.Any()).Return(nil, test.err)

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
		CredentialSubject: []map[string]any{{"id": "did:nuts:456"}},
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

			assert.EqualError(t, err, "invalid issuer did: invalid DID")
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
		CredentialSubject: []map[string]any{{"id": "did:nuts:456"}},
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
	t.Run("allowUntrustedIssuer is ignored for did:web", func(t *testing.T) {
		issuerURI := ssi.MustParseURI("did:web:example.com")
		credentialType := ssi.MustParseURI("ExampleType")

		allowUntrustedThatWillBeIgnored := false
		options := VCVerificationOptions{
			AllowUntrustedIssuer: &allowUntrustedThatWillBeIgnored,
		}

		expectedVC := vc.VerifiableCredential{
			Type:              []ssi.URI{credentialType},
			Issuer:            issuerURI,
			CredentialSubject: []map[string]any{{"id": "did:nuts:123"}},
		}

		expectedVerifyRequest := VCVerificationRequest{
			VerifiableCredential: expectedVC,
			VerificationOptions:  &options,
		}
		testContext := newMockContext(t)
		expectedResponse := VerifyVC200JSONResponse(VCVerificationResult{Validity: true})

		testContext.mockVerifier.EXPECT().Verify(expectedVC, true, true, nil)

		response, err := testContext.client.VerifyVC(testContext.requestCtx, VerifyVCRequestObject{Body: &expectedVerifyRequest})
		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
}

func TestWrapper_RevokeVC(t *testing.T) {
	credentialID := "did:nuts:123#abc"
	credentialURI := ssi.MustParseURI(credentialID)

	t.Run("test integration with vcr", func(t *testing.T) {
		t.Run("successful network revocation", func(t *testing.T) {
			testContext := newMockContext(t)
			expectedRevocation := &Revocation{Subject: credentialURI}
			testContext.mockIssuer.EXPECT().Revoke(gomock.Any(), credentialURI).Return(expectedRevocation, nil)
			expectedResponse := RevokeVC200JSONResponse(*expectedRevocation)

			response, err := testContext.client.RevokeVC(testContext.requestCtx, RevokeVCRequestObject{Id: credentialID})

			assert.NoError(t, err)
			assert.Equal(t, expectedResponse, response)
		})

		t.Run("successful statuslist revocation", func(t *testing.T) {
			testContext := newMockContext(t)
			testContext.mockIssuer.EXPECT().Revoke(gomock.Any(), credentialURI).Return(nil, nil)

			response, err := testContext.client.RevokeVC(testContext.requestCtx, RevokeVCRequestObject{Id: credentialID})

			assert.NoError(t, err)
			assert.Equal(t, RevokeVC204Response{}, response)
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

func TestWrapper_LoadVC(t *testing.T) {
	subjectID := "holder"
	t.Run("successful load", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{holderDID}, nil)
		testContext.mockVerifier.EXPECT().Verify(gomock.Any(), true, true, nil).Return(nil)
		testContext.mockWallet.EXPECT().Put(gomock.Any(), testVC).Return(nil)

		response, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &testVC})

		assert.NoError(t, err)
		assert.IsType(t, response, LoadVC204Response{})
	})
	t.Run("no DIDs for subject", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{}, didsubject.ErrSubjectNotFound)

		_, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &testVC})

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
	t.Run("verification failed", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{holderDID}, nil)
		testContext.mockVerifier.EXPECT().Verify(gomock.Any(), true, true, nil).Return(verifier.VerificationError{})

		_, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &testVC})

		httpErr, ok := err.(core.HTTPStatusCodeError)
		require.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.StatusCode())
	})
	t.Run("missing body", func(t *testing.T) {
		testContext := newMockContext(t)

		_, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID})

		assert.EqualError(t, err, "missing credential in body")
	})
	t.Run("invalid credentialSubject.ID", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{holderDID}, nil)

		_, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &vc.VerifiableCredential{ID: &credentialID}})

		assert.EqualError(t, err, "invalid credentialSubject.ID: unable to get subject DID from VC: there must be at least 1 credentialSubject")
	})
	t.Run("subject <> credentialSubject.ID mismatch", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{did.MustParseDID("did:test:unknown")}, nil)

		_, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &testVC})

		assert.EqualError(t, err, "subject does not own DID specified by credentialSubject.ID")
	})
	t.Run("wallet error", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{holderDID}, nil)
		testContext.mockVerifier.EXPECT().Verify(gomock.Any(), true, true, nil).Return(nil)
		testContext.mockWallet.EXPECT().Put(gomock.Any(), testVC).Return(assert.AnError)

		response, err := testContext.client.LoadVC(testContext.requestCtx, LoadVCRequestObject{SubjectID: subjectID, Body: &testVC})

		assert.Empty(t, response)
		assert.EqualError(t, err, assert.AnError.Error())
	})
}

func TestWrapper_GetCredentialsInWallet(t *testing.T) {
	subjectID := "holder"
	t.Run("ok", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{holderDID}, nil)
		testContext.mockWallet.EXPECT().List(testContext.requestCtx, holderDID).Return([]vc.VerifiableCredential{testVC}, nil)

		response, err := testContext.client.GetCredentialsInWallet(testContext.requestCtx, GetCredentialsInWalletRequestObject{
			SubjectID: subjectID,
		})

		assert.NoError(t, err)
		assert.Equal(t, GetCredentialsInWallet200JSONResponse([]vc.VerifiableCredential{testVC}), response)
	})
	t.Run("subject not found", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subjectID).Return([]did.DID{}, didsubject.ErrSubjectNotFound)

		_, err := testContext.client.GetCredentialsInWallet(testContext.requestCtx, GetCredentialsInWalletRequestObject{SubjectID: subjectID})

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
}

func TestWrapper_RemoveCredentialFromSubjectWallet(t *testing.T) {
	didNuts := did.MustParseDID("did:nuts:123")
	didWeb := did.MustParseDID("did:web:example.com")
	subject := "subbie"
	t.Run("ok", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(testContext.requestCtx, subject).Return([]did.DID{didNuts, didWeb}, nil)
		testContext.mockWallet.EXPECT().Remove(testContext.requestCtx, didNuts, credentialID).Return(nil)
		testContext.mockWallet.EXPECT().Remove(testContext.requestCtx, didWeb, credentialID).Return(types.ErrNotFound) // only exists on 1 DID

		response, err := testContext.client.RemoveCredentialFromWallet(testContext.requestCtx, RemoveCredentialFromWalletRequestObject{
			SubjectID: subject,
			Id:        credentialID.String(),
		})

		assert.NoError(t, err)
		assert.Equal(t, RemoveCredentialFromWallet204Response{}, response)
	})
	t.Run("#3761: prevent double-decode of credential ID", func(t *testing.T) {
		const subject = "some-subject"
		const credentialIDURIEncoded = "did:x509:0:sha256:GwlhBZuEFlSHXSRUXQuTs3_YpQxAahColwJJj35US1A::san:otherName:2.16.528.1.1007.99.2110-1-900025039-S-90000382-00.000-00000000::subject:L:%2527S-GRAVENHAGE:o:T%25C3%25A9st%2520Zorginstelling%252003%2316f51e20-0efb-44c8-a29d-fbbd42c26960"
		// did:x509:0:sha256:GwlhBZuEFlSHXSRUXQuTs3_YpQxAahColwJJj35US1A::san:otherName:2.16.528.1.1007.99.2110-1-900025039-S-90000382-00.000-00000000::subject:L:%2527S-GRAVENHAGE:o:T%25C3%25A9st%2520Zorginstelling%252003%2316f51e20-0efb-44c8-a29d-fbbd42c26960
		// did:x509:0:sha256:GwlhBZuEFlSHXSRUXQuTs3_YpQxAahColwJJj35US1A::san:otherName:2.16.528.1.1007.99.2110-1-900025039-S-90000382-00.000-00000000::subject:L:%27  S-GRAVENHAGE:o:T%C3%A9    st%20  Zorginstelling%20  03  #16f51e20-0efb-44c8-a29d-fbbd42c26960
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("DELETE", "/internal/vcr/v2/holder/"+subject+"/vc/"+credentialIDURIEncoded, nil)
		subjectDID := did.MustParseDID("did:web:example.com")
		credentialID := ssi.MustParseURI("did:x509:0:sha256:GwlhBZuEFlSHXSRUXQuTs3_YpQxAahColwJJj35US1A::san:otherName:2.16.528.1.1007.99.2110-1-900025039-S-90000382-00.000-00000000::subject:L:%27S-GRAVENHAGE:o:T%C3%A9st%20Zorginstelling%2003#16f51e20-0efb-44c8-a29d-fbbd42c26960")

		e := echo.New()
		testContext := newMockContext(t)
		testContext.client.Routes(e)
		testContext.mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), subject).Return([]did.DID{subjectDID}, nil)
		testContext.mockWallet.EXPECT().Remove(gomock.Any(), subjectDID, credentialID).Return(nil)
		e.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusNoContent, recorder.Code)
	})
	t.Run("error - credential not found", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(testContext.requestCtx, subject).Return([]did.DID{didNuts, didWeb}, nil)
		testContext.mockWallet.EXPECT().Remove(testContext.requestCtx, gomock.AnyOf(didNuts, didWeb), credentialID).Return(types.ErrNotFound).Times(2)

		response, err := testContext.client.RemoveCredentialFromWallet(testContext.requestCtx, RemoveCredentialFromWalletRequestObject{
			SubjectID: subject,
			Id:        credentialID.String(),
		})

		assert.Empty(t, response)
		assert.ErrorIs(t, err, types.ErrNotFound)
	})
	t.Run("error - subject not found", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(testContext.requestCtx, subject).Return(nil, didsubject.ErrSubjectNotFound)

		response, err := testContext.client.RemoveCredentialFromWallet(testContext.requestCtx, RemoveCredentialFromWalletRequestObject{
			SubjectID: subject,
			Id:        credentialID.String(),
		})

		assert.Empty(t, response)
		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
	t.Run("error - general error", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockSubjectManager.EXPECT().ListDIDs(testContext.requestCtx, subject).Return([]did.DID{didNuts, didWeb}, nil)
		testContext.mockWallet.EXPECT().Remove(testContext.requestCtx, didNuts, credentialID).Return(assert.AnError)

		response, err := testContext.client.RemoveCredentialFromWallet(testContext.requestCtx, RemoveCredentialFromWalletRequestObject{
			SubjectID: subject,
			Id:        credentialID.String(),
		})

		assert.Empty(t, response)
		assert.ErrorIs(t, err, assert.AnError)
	})
}

func TestWrapper_CreateVP(t *testing.T) {
	issuerURI := ssi.MustParseURI("did:nuts:123")
	credentialType := ssi.MustParseURI("ExampleType")

	subjectDID := did.MustParseDID("did:nuts:456")
	subjectDIDString := subjectDID.String()
	verifiableCredential := vc.VerifiableCredential{
		Type:              []ssi.URI{credentialType},
		Issuer:            issuerURI,
		CredentialSubject: []map[string]any{{"id": subjectDID.String()}},
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
		testContext.mockWallet.EXPECT().BuildPresentation(
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
		testContext.mockWallet.EXPECT().BuildPresentation(
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
		testContext.mockWallet.EXPECT().BuildPresentation(
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
		Proof: []interface{}{proof.LDProof{
			VerificationMethod: ssi.MustParseURI("did:nuts:123#this-is-my-key"),
			Signature:          "It's a very good proof. I know it because I made it myself. ALl the rest is fake.",
		}},
	}
	vpBS, _ := json.Marshal(vp)
	require.NoError(t, json.Unmarshal(vpBS, &vp))
	expectedVCs := []VerifiableCredential{vp.VerifiableCredential[0]}

	t.Run("ok", func(t *testing.T) {
		testContext := newMockContext(t)
		validAt, validAtStr := parsedTimeStr(time.Now())
		request := VPVerificationRequest{
			VerifiablePresentation: vp,
			ValidAt:                &validAtStr,
		}
		// assert that allowUntrustedVCs=false default for did:nuts
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, false, &validAt).Return(vp.VerifiableCredential, nil)
		expectedResponse := VerifyVP200JSONResponse(VPVerificationResult{
			Credentials: &expectedVCs,
			Validity:    true,
		})

		response, err := testContext.client.VerifyVP(testContext.requestCtx, VerifyVPRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("ok - did:web", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			VerifiableCredential: []VerifiableCredential{verifiableCredential},
			Proof: []interface{}{proof.LDProof{
				VerificationMethod: ssi.MustParseURI("did:web:example.com#secret-key"),
				Signature:          "It's a very good proof. I know it because I made it myself. ALl the rest is fake.",
			}},
		}
		vpBS, _ := json.Marshal(vp)
		require.NoError(t, json.Unmarshal(vpBS, &vp))

		testContext := newMockContext(t)
		validAt, validAtStr := parsedTimeStr(time.Now())
		request := VPVerificationRequest{
			VerifiablePresentation: vp,
			ValidAt:                &validAtStr,
		}
		// assert that allowUntrustedVCs=true default for did:web
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, true, &validAt).Return(vp.VerifiableCredential, nil)
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
	ctrl               *gomock.Controller
	mockIssuer         *issuer.MockIssuer
	mockSubjectManager *didsubject.MockManager
	mockVerifier       *verifier.MockVerifier
	mockWallet         *holder.MockWallet
	vcr                *vcr.MockVCR
	client             *Wrapper
	requestCtx         context.Context
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockVcr := vcr.NewMockVCR(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	mockWallet := holder.NewMockWallet(ctrl)
	mockVerifier := verifier.NewMockVerifier(ctrl)
	mockSubjectManager := didsubject.NewMockManager(ctrl)
	mockVcr.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	mockVcr.EXPECT().Wallet().Return(mockWallet).AnyTimes()
	mockVcr.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
	client := &Wrapper{VCR: mockVcr, ContextManager: jsonld.NewTestJSONLDManager(t), SubjectManager: mockSubjectManager}

	requestCtx := audit.TestContext()

	return mockContext{
		ctrl:               ctrl,
		mockIssuer:         mockIssuer,
		mockSubjectManager: mockSubjectManager,
		mockVerifier:       mockVerifier,
		mockWallet:         mockWallet,
		vcr:                mockVcr,
		client:             client,
		requestCtx:         requestCtx,
	}
}
