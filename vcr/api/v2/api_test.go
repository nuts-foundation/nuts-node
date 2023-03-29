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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"

	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"time"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/stretchr/testify/assert"
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

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			public := Public
			issueRequest := f.(*IssueVCRequest)
			issueRequest.Type = expectedRequestedVC.Type[0].String()
			issueRequest.Issuer = expectedRequestedVC.Issuer.String()
			issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
			issueRequest.Visibility = &public
			return nil
		})
		testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Eq(expectedRequestedVC), true, true)
		testContext.echo.EXPECT().JSON(http.StatusOK, nil)

		err := testContext.client.IssueVC(testContext.echo)
		assert.NoError(t, err)
	})

	t.Run("checking request params", func(t *testing.T) {

		t.Run("err - missing credential type", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				public := Public
				issueRequest := f.(*IssueVCRequest)
				//issueRequest.Type = expectedRequestedVC.Type[0].String()
				issueRequest.Issuer = expectedRequestedVC.Issuer.String()
				issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
				issueRequest.Visibility = &public
				return nil
			})
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "missing credential type")
		})

		t.Run("err - missing credentialSubject", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				public := Public
				issueRequest := f.(*IssueVCRequest)
				issueRequest.Type = expectedRequestedVC.Type[0].String()
				issueRequest.Issuer = expectedRequestedVC.Issuer.String()
				//issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
				issueRequest.Visibility = &public
				return nil
			})
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "missing credentialSubject")
		})
	})

	t.Run("test params", func(t *testing.T) {
		t.Run("publish is true", func(t *testing.T) {

			t.Run("ok - visibility private", func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					visibilityValue := Private
					issueRequest.Type = expectedRequestedVC.Type[0].String()
					issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
					issueRequest.Visibility = &visibilityValue
					issueRequest.PublishToNetwork = &publishValue
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), true, false)
				testContext.echo.EXPECT().JSON(http.StatusOK, nil)
				err := testContext.client.IssueVC(testContext.echo)
				assert.NoError(t, err)
			})

			t.Run("ok - visibility public", func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					visibilityValue := Public
					issueRequest.Type = expectedRequestedVC.Type[0].String()
					issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
					issueRequest.Visibility = &visibilityValue
					issueRequest.PublishToNetwork = &publishValue
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), true, true)
				testContext.echo.EXPECT().JSON(http.StatusOK, nil)
				err := testContext.client.IssueVC(testContext.echo)
				assert.NoError(t, err)
			})

			t.Run("err - visibility not set", func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					issueRequest.PublishToNetwork = &publishValue
					visibilityValue := IssueVCRequestVisibility("")
					issueRequest.Visibility = &visibilityValue
					return nil
				})
				err := testContext.client.IssueVC(testContext.echo)
				assert.EqualError(t, err, "visibility must be set when publishing credential")
			})

			t.Run("err - visibility contains invalid value", func(t *testing.T) {
				testContext := newMockContext(t)

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					issueRequest.PublishToNetwork = &publishValue
					visibilityValue := IssueVCRequestVisibility("only when it rains")
					issueRequest.Visibility = &visibilityValue
					return nil
				})
				err := testContext.client.IssueVC(testContext.echo)
				assert.EqualError(t, err, "invalid value for visibility")
			})

		})

		t.Run("err - publish false and visibility public", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				issueRequest := f.(*IssueVCRequest)
				publishValue := false
				issueRequest.PublishToNetwork = &publishValue
				visibilityValue := Private
				issueRequest.Visibility = &visibilityValue
				return nil
			})
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "visibility setting is only allowed when publishing to the network")
		})

		t.Run("publish is false", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				issueRequest := f.(*IssueVCRequest)
				publishValue := false
				issueRequest.PublishToNetwork = &publishValue
				issueRequest.Type = expectedRequestedVC.Type[0].String()
				issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
				return nil
			})
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), false, false)
			testContext.echo.EXPECT().JSON(http.StatusOK, nil)
			err := testContext.client.IssueVC(testContext.echo)
			assert.NoError(t, err)
		})
	})

	t.Run("test errors", func(t *testing.T) {
		validIssueRequest := func(f interface{}) {
			public := Public
			issueRequest := f.(*IssueVCRequest)
			issueRequest.Type = expectedRequestedVC.Type[0].String()
			issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
			issueRequest.Visibility = &public
		}

		t.Run("error - bind fails", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "b00m!")
		})

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

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					validIssueRequest(f)
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, test.err)

				err := testContext.client.IssueVC(testContext.echo)

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

		testContext.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{VerifiableCredentials: []SearchVCResult{}})

		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
			Subject:        &subjectIDString,
		}
		err := testContext.client.SearchIssuedVCs(testContext.echo, params)
		assert.NoError(t, err)
	})

	t.Run("ok - without subject, 1 result", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return([]VerifiableCredential{foundVC}, nil)
		testContext.mockVerifier.EXPECT().GetRevocation(vcID).Return(nil, verifier.ErrNotFound)
		testContext.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{VerifiableCredentials: []SearchVCResult{{VerifiableCredential: foundVC}}})

		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.SearchIssuedVCs(testContext.echo, params)
		assert.NoError(t, err)
	})

	t.Run("ok - without subject, 1 result, revoked", func(t *testing.T) {
		revocation := &Revocation{Reason: "because of reasons"}
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return([]VerifiableCredential{foundVC}, nil)
		testContext.mockVerifier.EXPECT().GetRevocation(vcID).Return(revocation, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{VerifiableCredentials: []SearchVCResult{{VerifiableCredential: foundVC, Revocation: revocation}}})

		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.SearchIssuedVCs(testContext.echo, params)
		assert.NoError(t, err)
	})

	t.Run("error - invalid input", func(t *testing.T) {

		t.Run("invalid issuer", func(t *testing.T) {
			testContext := newMockContext(t)

			params := SearchIssuedVCsParams{
				CredentialType: "TestCredential",
				Issuer:         "abc",
				Subject:        &subjectIDString,
			}
			err := testContext.client.SearchIssuedVCs(testContext.echo, params)
			assert.EqualError(t, err, "invalid issuer did: invalid DID: input length is less than 7")
		})

		t.Run("invalid subject", func(t *testing.T) {
			testContext := newMockContext(t)
			invalidSubjectStr := "%%"
			params := SearchIssuedVCsParams{
				CredentialType: "TestCredential",
				Issuer:         issuerID.String(),
				Subject:        &invalidSubjectStr,
			}
			err := testContext.client.SearchIssuedVCs(testContext.echo, params)
			assert.EqualError(t, err, "invalid subject id: parse \"%%\": invalid URL escape \"%%\"")
		})

		t.Run("invalid credentialType", func(t *testing.T) {
			testContext := newMockContext(t)
			params := SearchIssuedVCsParams{
				CredentialType: "%%",
				Issuer:         issuerID.String(),
				Subject:        &subjectIDString,
			}
			err := testContext.client.SearchIssuedVCs(testContext.echo, params)
			assert.EqualError(t, err, "invalid credentialType: parse \"%%\": invalid URL escape \"%%\"")
		})
	})

	t.Run("error - CredentialResolver returns error", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(testCredential, *issuerDID, nil).Return(nil, errors.New("b00m!"))

		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.SearchIssuedVCs(testContext.echo, params)
		assert.EqualError(t, err, "b00m!")
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

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VCVerificationRequest)
			*verifyRequest = expectedVerifyRequest
			return nil
		})

		testContext.echo.EXPECT().JSON(http.StatusOK, VCVerificationResult{Validity: true})

		testContext.mockVerifier.EXPECT().Verify(expectedVC, allowUntrusted, true, nil)

		err := testContext.client.VerifyVC(testContext.echo)
		assert.NoError(t, err)
	})
	t.Run("invalid vc", func(t *testing.T) {
		testContext := newMockContext(t)

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VCVerificationRequest)
			*verifyRequest = expectedVerifyRequest
			return nil
		})

		message := "invalid vc"
		testContext.echo.EXPECT().JSON(http.StatusOK, VCVerificationResult{Validity: false, Message: &message})

		testContext.mockVerifier.EXPECT().Verify(expectedVC, true, true, nil).Return(errors.New("invalid vc"))

		err := testContext.client.VerifyVC(testContext.echo)
		assert.NoError(t, err)
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
			testContext.echo.EXPECT().JSON(http.StatusOK, expectedRevocation)

			err := testContext.client.RevokeVC(testContext.echo, credentialID)
			assert.NoError(t, err)
		})

		t.Run("vcr returns an error", func(t *testing.T) {
			testContext := newMockContext(t)

			testContext.mockIssuer.EXPECT().Revoke(gomock.Any(), credentialURI).Return(nil, errors.New("credential not found"))
			err := testContext.client.RevokeVC(testContext.echo, credentialID)
			assert.EqualError(t, err, "credential not found")
		})
	})

	t.Run("param check", func(t *testing.T) {
		t.Run("invalid credential id format", func(t *testing.T) {
			testContext := newMockContext(t)

			err := testContext.client.RevokeVC(testContext.echo, "%%")
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
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockHolder.EXPECT().BuildVP(gomock.Any(), []VerifiableCredential{verifiableCredential}, proof.ProofOptions{Created: created}, nil, true).Return(result, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, result)

		err := testContext.client.CreateVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("ok - with signer DID", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		request.SignerDID = &subjectDIDString
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockHolder.EXPECT().BuildVP(gomock.Any(), []VerifiableCredential{verifiableCredential}, proof.ProofOptions{Created: created}, &subjectDID, true).Return(result, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, result)

		err := testContext.client.CreateVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("ok - with expires", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		expired, expiredStr := parsedTimeStr(created.Add(time.Hour))
		request.Expires = &expiredStr
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})
		opts := proof.ProofOptions{
			Created: created,
			Expires: &expired,
		}
		testContext.mockHolder.EXPECT().BuildVP(gomock.Any(), []VerifiableCredential{verifiableCredential}, opts, nil, true).Return(result, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, result)

		err := testContext.client.CreateVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("error - with expires, but in the past", func(t *testing.T) {
		testContext := newMockContext(t)
		expired := time.Time{}
		request := createRequest()
		expiredStr := expired.Format(time.RFC3339)
		request.Expires = &expiredStr
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})

		err := testContext.client.CreateVP(testContext.echo)

		assert.EqualError(t, err, "expires can not lay in the past")
	})
	t.Run("error - invalid expires format", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		expiredStr := "a"
		request.Expires = &expiredStr
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})

		err := testContext.client.CreateVP(testContext.echo)

		assert.Contains(t, err.Error(), "invalid value for expires")
	})
	t.Run("error - no VCs", func(t *testing.T) {
		testContext := newMockContext(t)
		request := CreateVPRequest{}
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})

		err := testContext.client.CreateVP(testContext.echo)

		assert.EqualError(t, err, "verifiableCredentials needs at least 1 item")
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
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VPVerificationRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, &validAt).Return(vp.VerifiableCredential, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, VPVerificationResult{
			Credentials: &expectedVCs,
			Validity:    true,
		})

		err := testContext.client.VerifyVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("ok - verifyCredentials set", func(t *testing.T) {
		testContext := newMockContext(t)
		verifyCredentials := false
		request := VPVerificationRequest{VerifiablePresentation: vp, VerifyCredentials: &verifyCredentials}
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VPVerificationRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockVerifier.EXPECT().VerifyVP(vp, false, nil).Return(vp.VerifiableCredential, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, VPVerificationResult{
			Credentials: &expectedVCs,
			Validity:    true,
		})

		err := testContext.client.VerifyVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("error - verification failed (other error)", func(t *testing.T) {
		testContext := newMockContext(t)
		request := VPVerificationRequest{VerifiablePresentation: vp}
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VPVerificationRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, nil).Return(nil, errors.New("failed"))

		err := testContext.client.VerifyVP(testContext.echo)

		assert.Error(t, err)
	})
	t.Run("error - invalid validAt format", func(t *testing.T) {
		testContext := newMockContext(t)
		validAtStr := "a"
		request := VPVerificationRequest{
			VerifiablePresentation: vp,
			ValidAt:                &validAtStr,
		}
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VPVerificationRequest)
			*verifyRequest = request
			return nil
		})

		err := testContext.client.VerifyVP(testContext.echo)

		assert.Contains(t, err.Error(), "invalid value for validAt")
	})
	t.Run("error - verification failed (verification error)", func(t *testing.T) {
		testContext := newMockContext(t)
		request := VPVerificationRequest{VerifiablePresentation: vp}
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VPVerificationRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockVerifier.EXPECT().VerifyVP(vp, true, nil).Return(nil, verifier.VerificationError{})
		errMsg := "verification error: "
		testContext.echo.EXPECT().JSON(http.StatusOK, gomock.Eq(VPVerificationResult{
			Message:  &errMsg,
			Validity: false,
		}))

		err := testContext.client.VerifyVP(testContext.echo)

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

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.TrustIssuer(ctx.echo)
		assert.NoError(t, err)
	})

	t.Run("ok - remove", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Untrust(cType, issuer).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.UntrustIssuer(ctx.echo)
		assert.NoError(t, err)
	})

	t.Run("error - invalid issuer", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = string([]byte{0})
			return nil
		})

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "failed to parse issuer: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = string([]byte{0})
			capturedCombination.Issuer = cType.String()
			return nil
		})

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - invalid body", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			return errors.New("b00m!")
		})

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - failed to add", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(errors.New("b00m!"))

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.Error(t, err)
	})
}

func TestWrapper_Trusted(t *testing.T) {
	credentialType, _ := ssi.ParseURI("type")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		var capturedList []string
		ctx.vcr.EXPECT().Trusted(*credentialType).Return([]ssi.URI{*credentialType}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f1 interface{}, f2 interface{}) error {
			capturedList = f2.([]string)
			return nil
		})

		err := ctx.client.ListTrusted(ctx.echo, credentialType.String())

		require.NoError(t, err)

		assert.Len(t, capturedList, 1)
		assert.Equal(t, credentialType.String(), capturedList[0])
	})

	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.ListTrusted(ctx.echo, string([]byte{0}))

		assert.Error(t, err)
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})
}

func TestWrapper_Untrusted(t *testing.T) {
	credentialType, _ := ssi.ParseURI("type")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		var capturedList []string
		ctx.vcr.EXPECT().Untrusted(*credentialType).Return([]ssi.URI{*credentialType}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f1 interface{}, f2 interface{}) error {
			capturedList = f2.([]string)
			return nil
		})

		err := ctx.client.ListUntrusted(ctx.echo, credentialType.String())

		require.NoError(t, err)

		assert.Len(t, capturedList, 1)
		assert.Equal(t, credentialType.String(), capturedList[0])
	})

	t.Run("error - malformed input", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.ListUntrusted(ctx.echo, string([]byte{0}))

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Untrusted(*credentialType).Return(nil, errors.New("b00m!"))

		err := ctx.client.ListUntrusted(ctx.echo, credentialType.String())

		assert.EqualError(t, err, "b00m!")
	})
}

func TestWrapper_Preprocess(t *testing.T) {
	w := &Wrapper{}
	echoCtx := echo.New().NewContext(&http.Request{}, nil)
	echoCtx.Set(core.UserContextKey, "user")

	w.Preprocess("foo", echoCtx)

	audit.AssertAuditInfo(t, echoCtx, "user@", "VCR", "foo")
	assert.Equal(t, "foo", echoCtx.Get(core.OperationIDContextKey))
	assert.Equal(t, "VCR", echoCtx.Get(core.ModuleNameContextKey))
	assert.Same(t, w, echoCtx.Get(core.StatusCodeResolverContextKey))
}

type mockContext struct {
	ctrl         *gomock.Controller
	echo         *mock.MockContext
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
	echoMock := mock.NewMockContext(ctrl)
	request, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, "/", nil)
	echoMock.EXPECT().Request().Return(request).AnyTimes()

	return mockContext{
		ctrl:         ctrl,
		echo:         echoMock,
		mockIssuer:   mockIssuer,
		mockHolder:   mockHolder,
		mockVerifier: mockVerifier,
		vcr:          mockVcr,
		client:       client,
		requestCtx:   requestCtx,
	}
}
