package services

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

var holder = *vdr.RandomDID

func TestResolveEndpointURL(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectedURI, _ := did.ParseURI("http://nuts.nl")
		s := did.Service{Type: "oauth", ServiceEndpoint: expectedURI.String()}
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(&did.Document{Service: []did.Service{s}}, nil, nil)
		_, endpointURL, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.NoError(t, err)
		assert.Equal(t, expectedURI.String(), endpointURL)
	})
	t.Run("unable to resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(holder, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		_, _, err := ResolveEndpointURL(resolver, holder, "oauth", nil)
		assert.Error(t, err)
	})
}
