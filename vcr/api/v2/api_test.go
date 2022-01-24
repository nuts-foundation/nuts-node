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
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestWrapper_IssueVC(t *testing.T) {
	t.Run("ok - empty post body", func(t *testing.T) {
		testContext := newMockContext(t)
		defer testContext.ctrl.Finish()

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			issueRequest := f.(*IssueVCRequest)
			public := IssueVCRequestVisibilityPublic
			issueRequest.Visibility = &public
			return nil
		})
		testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, false)
		testContext.echo.EXPECT().JSON(http.StatusOK, nil)
		err := testContext.client.IssueVC(testContext.echo)
		assert.NoError(t, err)
	})

	t.Run("ok with actual credential", func(t *testing.T) {
		testContext := newMockContext(t)
		defer testContext.ctrl.Finish()
		issuerURI, _ := ssi.ParseURI("did:nuts:123")
		credentialType, _ := ssi.ParseURI("ExampleType")

		expectedRequestedVC := vc.VerifiableCredential{
			Type:              []ssi.URI{*credentialType},
			Issuer:            *issuerURI,
			CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
		}

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			public := IssueVCRequestVisibilityPublic
			issueRequest := f.(*IssueVCRequest)
			issueRequest.Type = expectedRequestedVC.Type[0].String()
			issueRequest.Issuer = expectedRequestedVC.Issuer.String()
			issueRequest.CredentialSubject = expectedRequestedVC.CredentialSubject
			issueRequest.Visibility = &public
			return nil
		})
		testContext.mockIssuer.EXPECT().Issue(gomock.Eq(expectedRequestedVC), true, false)
		testContext.echo.EXPECT().JSON(http.StatusOK, nil)

		err := testContext.client.IssueVC(testContext.echo)
		assert.NoError(t, err)
	})

	t.Run("test params", func(t *testing.T) {
		t.Run("publish is true", func(t *testing.T) {

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

			t.Run("ok - visibility private", func(t *testing.T) {
				testContext := newMockContext(t)
				defer testContext.ctrl.Finish()

				testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
					issueRequest := f.(*IssueVCRequest)
					publishValue := true
					visibilityValue := IssueVCRequestVisibilityPublic
					issueRequest.Visibility = &visibilityValue
					issueRequest.PublishToNetwork = &publishValue
					return nil
				})
				testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, false)
				testContext.echo.EXPECT().JSON(http.StatusOK, nil)
				err := testContext.client.IssueVC(testContext.echo)
				assert.NoError(t, err)
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
				issueRequest.Visibility = &public
				return nil
			})
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("could not issue"))
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "could not issue")

		})
	})
}

func TestWrapper_ResolveIssuedVC(t *testing.T) {
	subjectID, _ := ssi.ParseURI("did:nuts:456")
	issuerID, _ := did.ParseDID("did:nuts:123")
	subjectIDString := subjectID.String()
	contextURI, _ := ssi.ParseURI("")
	testCredential, _ := ssi.ParseURI("TestCredential")

	t.Run("ok - with subject", func(t *testing.T) {
		testContext := newMockContext(t)
		issuerStoreMock := issuer.NewMockStoreResolver(testContext.ctrl)
		issuerStoreMock.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerID, subjectID)

		testContext.echo.EXPECT().JSON(http.StatusOK, nil)

		testContext.mockIssuer.EXPECT().CredentialResolver().Return(issuerStoreMock)

		params := ResolveIssuedVCParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
			Subject:        &subjectIDString,
		}
		err := testContext.client.ResolveIssuedVC(testContext.echo, params)
		assert.NoError(t, err)
	})

	t.Run("ok - without subject", func(t *testing.T) {
		testContext := newMockContext(t)
		issuerStoreMock := issuer.NewMockStoreResolver(testContext.ctrl)
		issuerStoreMock.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerID, nil)

		testContext.echo.EXPECT().JSON(http.StatusOK, nil)

		testContext.mockIssuer.EXPECT().CredentialResolver().Return(issuerStoreMock)

		params := ResolveIssuedVCParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.ResolveIssuedVC(testContext.echo, params)
		assert.NoError(t, err)
	})

	t.Run("error - invalid input", func(t *testing.T) {

		t.Run("invalid issuer", func(t *testing.T) {
			testContext := newMockContext(t)

			params := ResolveIssuedVCParams{
				CredentialType: "TestCredential",
				Issuer:         "abc",
				Subject:        &subjectIDString,
			}
			err := testContext.client.ResolveIssuedVC(testContext.echo, params)
			assert.EqualError(t, err, "invalid issuer did: invalid DID: input length is less than 7")
		})

		t.Run("invalid subject", func(t *testing.T) {
			testContext := newMockContext(t)
			invalidSubjectStr := "%%"
			params := ResolveIssuedVCParams{
				CredentialType: "TestCredential",
				Issuer:         issuerID.String(),
				Subject:        &invalidSubjectStr,
			}
			err := testContext.client.ResolveIssuedVC(testContext.echo, params)
			assert.EqualError(t, err, "invalid subject id: parse \"%%\": invalid URL escape \"%%\"")
		})

		t.Run("invalid credentialType", func(t *testing.T) {
			testContext := newMockContext(t)
			params := ResolveIssuedVCParams{
				CredentialType: "%%",
				Issuer:         issuerID.String(),
				Subject:        &subjectIDString,
			}
			err := testContext.client.ResolveIssuedVC(testContext.echo, params)
			assert.EqualError(t, err, "invalid credentialType: parse \"%%\": invalid URL escape \"%%\"")
		})
	})

	t.Run("error - CredentialResolver returns error", func(t *testing.T) {
		testContext := newMockContext(t)
		issuerStoreMock := issuer.NewMockStoreResolver(testContext.ctrl)
		issuerStoreMock.EXPECT().SearchCredential(*contextURI, *testCredential, *issuerID, nil).Return(nil, errors.New("b00m!"))

		testContext.mockIssuer.EXPECT().CredentialResolver().Return(issuerStoreMock)

		params := ResolveIssuedVCParams{
			CredentialType: "TestCredential",
			Issuer:         issuerID.String(),
		}
		err := testContext.client.ResolveIssuedVC(testContext.echo, params)
		assert.EqualError(t, err, "b00m!")
	})
}

func TestWrapper_VerifyVC(t *testing.T) {
	t.Run("valid vc", func(t *testing.T) {
		testContext := newMockContext(t)

		issuerURI, _ := ssi.ParseURI("did:nuts:123")
		credentialType, _ := ssi.ParseURI("ExampleType")

		expectedRequestedVC := vc.VerifiableCredential{
			Type:              []ssi.URI{*credentialType},
			Issuer:            *issuerURI,
			CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
		}

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VerifiableCredential)
			*verifyRequest = expectedRequestedVC
			return nil
		})

		testContext.echo.EXPECT().JSON(http.StatusOK, VCVerificationResult{Validity: true})

		testContext.vcr.EXPECT().Validate(expectedRequestedVC, true, true, nil)

		err := testContext.client.VerifyVC(testContext.echo)
		assert.NoError(t, err)
	})
	t.Run("invalid vc", func(t *testing.T) {
		testContext := newMockContext(t)

		issuerURI, _ := ssi.ParseURI("did:nuts:123")
		credentialType, _ := ssi.ParseURI("ExampleType")

		expectedRequestedVC := vc.VerifiableCredential{
			Type:              []ssi.URI{*credentialType},
			Issuer:            *issuerURI,
			CredentialSubject: []interface{}{map[string]interface{}{"id": "did:nuts:456"}},
		}

		testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			verifyRequest := f.(*VerifiableCredential)
			*verifyRequest = expectedRequestedVC
			return nil
		})

		message := "invalid vc"
		testContext.echo.EXPECT().JSON(http.StatusOK, VCVerificationResult{Validity: false, Message: &message})

		testContext.vcr.EXPECT().Validate(expectedRequestedVC, true, true, nil).Return(errors.New("invalid vc"))

		err := testContext.client.VerifyVC(testContext.echo)
		assert.NoError(t, err)
	})
}

func TestWrapper_RevokeVC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	w := &Wrapper{}
	ctx := mock.NewMockContext(ctrl)
	err := w.RevokeVC(ctx, "")
	assert.EqualError(t, err, "not yet implemented, use the v1 api")
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
	vcr        *vcr.MockVCR
	client     *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	mockVcr := vcr.NewMockVCR(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	mockVcr.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	client := &Wrapper{VCR: mockVcr}

	return mockContext{
		ctrl:       ctrl,
		echo:       mock.NewMockContext(ctrl),
		mockIssuer: mockIssuer,
		vcr:        mockVcr,
		client:     client,
	}
}
