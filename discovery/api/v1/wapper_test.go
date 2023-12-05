package v1

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

const serviceID = "wonderland"

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
		wrapper: Wrapper{server},
	}
}
