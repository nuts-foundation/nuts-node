package services

import (
	ssi "github.com/nuts-foundation/go-did"
	"fmt"
	"testing"

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
	compoundService := did.Service{Type: serviceType, ServiceEndpoint: compoundServiceType{OAuthEndpointType: fmt.Sprintf("%s?type=oauth", endpointDIDDoc.String())}}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{compoundService}}, nil, nil)
		resolver.EXPECT().Resolve(endpointDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{oauthService}}, nil, nil)

		_, endpointURL, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.NoError(t, err)
		assert.Equal(t, expectedURI.String(), endpointURL)
	})

	t.Run("error - unable to resolve service did doc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - no services in did Doc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service without required type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: compoundServiceType{"not_oauth": fmt.Sprintf("%s?type=oauth", endpointDIDDoc.String())}}}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service with incorrect URI reference", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: compoundServiceType{"oauth": string([]byte{0})}}}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - compound service with incorrect DID reference", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: compoundServiceType{"oauth": "not_a_did"}}}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - unknown endpoint service ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{compoundService}}, nil, nil)
		resolver.EXPECT().Resolve(endpointDIDDoc, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - no type in endpoint ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: compoundServiceType{"oauth": "did:nuts:1"}}}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})

	t.Run("error - too many types in endpoint ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(serviceDIDDoc, gomock.Any()).Return(&did.Document{Service: []did.Service{{Type: serviceType, ServiceEndpoint: compoundServiceType{"oauth": "did:nuts:1?type=a&type=b"}}}}, nil, nil)

		_, _, err := ResolveServiceURL(resolver, serviceDIDDoc, serviceType, OAuthEndpointType, nil)

		assert.Error(t, err)
	})
}
