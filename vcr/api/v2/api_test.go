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
	"errors"
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
	"net/http"
	"testing"
	"time"
)

func TestWrapper_IssueVC(t *testing.T) {

	issuerURI, _ := ssi.ParseURI("did:nuts:123")
	credentialType, _ := ssi.ParseURI("ExampleType")

	expectedRequestedVC := vc.VerifiableCredential{
		Type:              []ssi.URI{*credentialType},
		Issuer:            *issuerURI,
		CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
	}

	t.Run("ok with an actual credential", func(t *testing.T) {
		testContext := newMockContext(t)
		defer testContext.ctrl.Finish()

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			public := IssueVCRequestVisibilityPublic
			issueRequest := f.(*IssueVCRequest)
			issueRequest.Type = expectedRequestedVC.Type[0].String()
			issueRequest.Issuer = expectedRequestedVC.Issuer.String()
			issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
			issueRequest.Visibility = &public
			return nil
		})
		testContext.mockIssuer.EXPECT().Issue(gomock.Eq(expectedRequestedVC), true, true)
		testContext.echo.EXPECT().JSON(http.StatusOK, nil)

		err := testContext.client.IssueVC(testContext.echo)
		assert.NoError(t, err)
	})

	t.Run("checking request params", func(t *testing.T) {

		t.Run("err - missing credential type", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				public := IssueVCRequestVisibilityPublic
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
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				public := IssueVCRequestVisibilityPublic
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
				defer testContext.ctrl.Finish()

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					visibilityValue := IssueVCRequestVisibilityPrivate
					issueRequest.Type = expectedRequestedVC.Type[0].String()
					issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
					issueRequest.Visibility = &visibilityValue
					issueRequest.PublishToNetwork = &publishValue
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, false)
				testContext.echo.EXPECT().JSON(http.StatusOK, nil)
				err := testContext.client.IssueVC(testContext.echo)
				assert.NoError(t, err)
			})

			t.Run("ok - visibility public", func(t *testing.T) {
				testContext := newMockContext(t)
				defer testContext.ctrl.Finish()

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					visibilityValue := IssueVCRequestVisibilityPublic
					issueRequest.Type = expectedRequestedVC.Type[0].String()
					issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
					issueRequest.Visibility = &visibilityValue
					issueRequest.PublishToNetwork = &publishValue
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, true)
				testContext.echo.EXPECT().JSON(http.StatusOK, nil)
				err := testContext.client.IssueVC(testContext.echo)
				assert.NoError(t, err)
			})

			t.Run("err - visibility not set", func(t *testing.T) {
				testContext := newMockContext(t)
				defer testContext.ctrl.Finish()

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
				defer testContext.ctrl.Finish()

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
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				issueRequest := f.(*IssueVCRequest)
				publishValue := false
				issueRequest.PublishToNetwork = &publishValue
				visibilityValue := IssueVCRequestVisibilityPrivate
				issueRequest.Visibility = &visibilityValue
				return nil
			})
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "visibility setting is only allowed when publishing to the network")
		})

		t.Run("publish is false", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				issueRequest := f.(*IssueVCRequest)
				publishValue := false
				issueRequest.PublishToNetwork = &publishValue
				issueRequest.Type = expectedRequestedVC.Type[0].String()
				issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
				return nil
			})
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), false, false)
			testContext.echo.EXPECT().JSON(http.StatusOK, nil)
			err := testContext.client.IssueVC(testContext.echo)
			assert.NoError(t, err)
		})
	})

	t.Run("test errors", func(t *testing.T) {
		t.Run("error - bind fails", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "b00m!")
		})

		t.Run("error - issue returns error", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				public := IssueVCRequestVisibilityPublic
				issueRequest := f.(*IssueVCRequest)
				issueRequest.Type = expectedRequestedVC.Type[0].String()
				issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
				issueRequest.Visibility = &public
				return nil
			})
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("could not issue"))
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "could not issue")

		})
	})
}

func TestWrapper_SearchIssuedVCs(t *testing.T) {
	subjectID, _ := ssi.ParseURI("did:nuts:456")
	issuerDID, _ := did.ParseDID("did:nuts:123")
	issuerID, _ := ssi.ParseURI(issuerDID.String())
	subjectIDString := subjectID.String()
	contextURI, _ := ssi.ParseURI("")
	testCredential, _ := ssi.ParseURI("TestCredential")

	foundVC := vc.VerifiableCredential{
		Type:              []ssi.URI{*testCredential},
		Issuer:            *issuerID,
		CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
	}

	t.Run("ok - with subject, no results", func(t *testing.T) {
		testContext := newMockContext(t)
		testContext.mockIssuer.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerDID, subjectID)

		testContext.echo.EXPECT().JSON(http.StatusOK, []SearchVCResult{})

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
		testContext.mockIssuer.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerDID, nil).Return([]VerifiableCredential{foundVC}, nil)

		testContext.echo.EXPECT().JSON(http.StatusOK, []SearchVCResult{{VerifiableCredential: foundVC}})

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
		testContext.mockIssuer.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerDID, nil).Return(nil, errors.New("b00m!"))

		params := SearchIssuedVCsParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.SearchIssuedVCs(testContext.echo, params)
		assert.EqualError(t, err, "b00m!")
	})
}

func TestWrapper_VerifyVC(t *testing.T) {
	issuerURI, _ := ssi.ParseURI("did:nuts:123")
	credentialType, _ := ssi.ParseURI("ExampleType")

	allowUntrusted := true
	options := VCVerificationOptions{
		AllowUntrustedIssuer: &allowUntrusted,
	}

	expectedVC := vc.VerifiableCredential{
		Type:              []ssi.URI{*credentialType},
		Issuer:            *issuerURI,
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

		testContext.vcr.EXPECT().Validate(expectedVC, allowUntrusted, true, nil)

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

		testContext.vcr.EXPECT().Validate(expectedVC, true, true, nil).Return(errors.New("invalid vc"))

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
			defer testContext.ctrl.Finish()

			expectedRevocation := &Revocation{Subject: credentialURI}
			testContext.vcr.EXPECT().Revoke(credentialURI).Return(expectedRevocation, nil)
			testContext.echo.EXPECT().JSON(http.StatusOK, expectedRevocation)

			err := testContext.client.RevokeVC(testContext.echo, credentialID)
			assert.NoError(t, err)
		})

		t.Run("vcr returns an error", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.vcr.EXPECT().Revoke(credentialURI).Return(nil, errors.New("credential not found"))
			err := testContext.client.RevokeVC(testContext.echo, credentialID)
			assert.EqualError(t, err, "credential not found")
		})
	})

	t.Run("param check", func(t *testing.T) {
		t.Run("invalid credential id format", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			err := testContext.client.RevokeVC(testContext.echo, "%%")
			assert.EqualError(t, err, "invalid credential id: parse \"%%\": invalid URL escape \"%%\"")
		})

	})
}

func TestWrapper_CreateVP(t *testing.T) {
	issuerURI, _ := ssi.ParseURI("did:nuts:123")
	credentialType, _ := ssi.ParseURI("ExampleType")

	subjectDID := did.MustParseDID("did:nuts:456")
	subjectDIDString := subjectDID.String()
	verifiableCredential := vc.VerifiableCredential{
		Type:              []ssi.URI{*credentialType},
		Issuer:            *issuerURI,
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

	t.Run("ok - without signer DID", func(t *testing.T) {
		testContext := newMockContext(t)
		request := createRequest()
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})
		testContext.mockHolder.EXPECT().BuildVP([]VerifiableCredential{verifiableCredential}, proof.ProofOptions{Created: created}, nil, true).Return(result, nil)
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
		testContext.mockHolder.EXPECT().BuildVP([]VerifiableCredential{verifiableCredential}, proof.ProofOptions{Created: created}, &subjectDID, true).Return(result, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, result)

		err := testContext.client.CreateVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("ok - with expires", func(t *testing.T) {
		testContext := newMockContext(t)
		expired := created.Add(time.Hour)
		request := createRequest()
		request.Expires = &expired
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})
		opts := proof.ProofOptions{
			Created:        created,
			ExpirationDate: &expired,
		}
		testContext.mockHolder.EXPECT().BuildVP([]VerifiableCredential{verifiableCredential}, opts, nil, true).Return(result, nil)
		testContext.echo.EXPECT().JSON(http.StatusOK, result)

		err := testContext.client.CreateVP(testContext.echo)

		assert.NoError(t, err)
	})
	t.Run("error - with expires, but in the past", func(t *testing.T) {
		testContext := newMockContext(t)
		expired := time.Time{}
		request := createRequest()
		request.Expires = &expired
		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*CreateVPRequest)
			*verifyRequest = request
			return nil
		})

		err := testContext.client.CreateVP(testContext.echo)

		assert.EqualError(t, err, "expires can not lay in the past")
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

func TestWrapper_Preprocess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	w := &Wrapper{}
	ctx := mock.NewMockContext(ctrl)
	ctx.EXPECT().Set(core.StatusCodeResolverContextKey, w)
	ctx.EXPECT().Set(core.OperationIDContextKey, "foo")
	ctx.EXPECT().Set(core.ModuleNameContextKey, "VCR")

	w.Preprocess("foo", ctx)
}

type mockContext struct {
	ctrl       *gomock.Controller
	echo       *mock.MockContext
	mockIssuer *issuer.MockIssuer
	mockHolder *holder.MockHolder
	vcr        *vcr.MockVCR
	client     *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockVcr := vcr.NewMockVCR(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	mockHolder := holder.NewMockHolder(ctrl)
	mockVcr.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	mockVcr.EXPECT().Holder().Return(mockHolder).AnyTimes()
	client := &Wrapper{VCR: mockVcr}

	return mockContext{
		ctrl:       ctrl,
		echo:       mock.NewMockContext(ctrl),
		mockIssuer: mockIssuer,
		mockHolder: mockHolder,
		vcr:        mockVcr,
		client:     client,
	}
}
