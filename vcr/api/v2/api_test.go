package v2

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestWrapper_ResolveIssuedVC(t *testing.T) {
}

func TestWrapper_IssueVC(t *testing.T) {
	t.Run("ok - empty post body", func(t *testing.T) {
		testContext := newMockContext(t)
		defer testContext.ctrl.Finish()

		testContext.echo.EXPECT().Bind(gomock.Any())
		testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, false)
		testContext.echo.EXPECT().JSON(http.StatusOK, nil)
		err := testContext.client.IssueVC(testContext.echo)
		assert.NoError(t, err)
	})

	t.Run("test params", func(t *testing.T) {
		t.Run("publish is true, visibility not set", func(t *testing.T) {
			testContext := newMockContext(t)
			defer testContext.ctrl.Finish()

			testContext.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
				issueRequest := f.(*IssueVCRequest)
				publishValue := true
				issueRequest.PublishToNetwork = &publishValue
				return nil
			})
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, false)
			testContext.echo.EXPECT().JSON(http.StatusOK, nil)
			err := testContext.client.IssueVC(testContext.echo)
			assert.NoError(t, err)
		})

		t.Run("publish is true, visibility private", func(t *testing.T) {
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
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), true, true)
			testContext.echo.EXPECT().JSON(http.StatusOK, nil)
			err := testContext.client.IssueVC(testContext.echo)
			assert.NoError(t, err)
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
			assert.EqualError(t, err, "visibility setting is only valid when publishing to the network")
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

			testContext.echo.EXPECT().Bind(gomock.Any())
			testContext.mockIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("could not issue"))
			err := testContext.client.IssueVC(testContext.echo)
			assert.EqualError(t, err, "could not issue")

		})
	})
}

type mockContext struct {
	ctrl *gomock.Controller
	echo *mock.MockContext
	//registry *concept.MockRegistry
	mockIssuer *issuer.MockIssuer
	//vcr      *vcr.MockVCR
	client *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	//registry := concept.NewMockRegistry(ctrl)
	vcr := vcr.NewMockVCR(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	vcr.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	client := &Wrapper{VCR: vcr}

	return mockContext{
		ctrl:       ctrl,
		echo:       mock.NewMockContext(ctrl),
		mockIssuer: mockIssuer,
		//registry: registry,
		//vcr:      vcr,
		client: client,
	}
}
