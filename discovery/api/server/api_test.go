package v1

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
)

const serviceID = "wonderland"

var subjectDID = did.MustParseDID("did:web:example.com")

func TestWrapper_GetPresentations(t *testing.T) {
	t.Run("no tag", func(t *testing.T) {
		latestTag := discovery.Tag("latest")
		test := newMockContext(t)
		presentations := []vc.VerifiablePresentation{}
		test.server.EXPECT().Get(serviceID, nil).Return(presentations, &latestTag, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{ServiceID: serviceID})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, latestTag, discovery.Tag(response.(GetPresentations200JSONResponse).Tag))
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
	t.Run("with tag", func(t *testing.T) {
		givenTag := discovery.Tag("given")
		latestTag := discovery.Tag("latest")
		test := newMockContext(t)
		presentations := []vc.VerifiablePresentation{}
		test.server.EXPECT().Get(serviceID, &givenTag).Return(presentations, &latestTag, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{
			ServiceID: serviceID,
			Params: GetPresentationsParams{
				Tag: (*string)(&givenTag),
			},
		})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, latestTag, discovery.Tag(response.(GetPresentations200JSONResponse).Tag))
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		test.server.EXPECT().Get(serviceID, nil).Return(nil, nil, errors.New("foo"))

		_, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{ServiceID: serviceID})

		assert.Error(t, err)
	})
}

func TestWrapper_RegisterPresentation(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		presentation := vc.VerifiablePresentation{}
		test.server.EXPECT().Register(serviceID, presentation).Return(nil)

		response, err := test.wrapper.RegisterPresentation(nil, RegisterPresentationRequestObject{
			ServiceID: serviceID,
			Body:      &presentation,
		})

		assert.NoError(t, err)
		assert.IsType(t, RegisterPresentation201Response{}, response)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		presentation := vc.VerifiablePresentation{}
		test.server.EXPECT().Register(serviceID, presentation).Return(discovery.ErrInvalidPresentation)

		_, err := test.wrapper.RegisterPresentation(nil, RegisterPresentationRequestObject{
			ServiceID: serviceID,
			Body:      &presentation,
		})

		assert.ErrorIs(t, err, discovery.ErrInvalidPresentation)
	})
}

func TestWrapper_ResolveStatusCode(t *testing.T) {
	expected := map[error]int{
		discovery.ErrServerModeDisabled:  http.StatusBadRequest,
		discovery.ErrInvalidPresentation: http.StatusBadRequest,
		errors.New("foo"):                http.StatusInternalServerError,
	}
	wrapper := Wrapper{}
	for err, expectedCode := range expected {
		t.Run(err.Error(), func(t *testing.T) {
			assert.Equal(t, expectedCode, wrapper.ResolveStatusCode(err))
		})
	}
}

type mockContext struct {
	ctrl    *gomock.Controller
	server  *discovery.MockServer
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	server := discovery.NewMockServer(ctrl)
	return mockContext{
		ctrl:    ctrl,
		server:  server,
		wrapper: Wrapper{Server: server},
	}
}
