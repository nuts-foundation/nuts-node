package services

import (
	"fmt"
	"testing"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

var serviceDIDDoc = *vdr.TestDIDA
var endpointDIDDoc = *vdr.TestDIDB

func TestResolveEndpointURL(t *testing.T) {
	serviceType := "service"
	expectedURI, _ := ssi.ParseURI("http://nuts.nl")
	oauthService := did.Service{Type: OAuthEndpointType, ServiceEndpoint: expectedURI.String()}
	cService := did.Service{Type: serviceType, ServiceEndpoint: types.CompoundService{OAuthEndpointType: fmt.Sprintf("%s?type=oauth", endpointDIDDoc.String())}}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{cService}}, nil, nil)
		resolver.EXPECT().Resolve(endpointDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{oauthService}}, nil, nil)

		_, endpointURL, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.NoError(t, err)
		assert.Equal(t, expectedURI.String(), endpointURL)
	})

	t.Run("error - unable to resolve service did doc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - no services in did Doc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service without required type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: types.CompoundService{"not_oauth": fmt.Sprintf("%s?type=oauth", endpointDIDDoc.String())}}}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service with incorrect URI reference", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: types.CompoundService{"oauth": string([]byte{0})}}}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service with incorrect DID reference", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: types.CompoundService{"oauth": "not_a_did"}}}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - unknown endpoint service ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{cService}}, nil, nil)
		resolver.EXPECT().Resolve(endpointDIDDoc, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - no type in endpoint ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: types.CompoundService{"oauth": "did:nuts:1"}}}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - too many types in endpoint ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: types.CompoundService{"oauth": "did:nuts:1?type=a&type=b"}}}}, nil, nil)

		_, _, err := ResolveCompoundServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})
}
