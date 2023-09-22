/*
 * Copyright (C) 2023 Nuts community
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

package iam

import (
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/url"
	"testing"
)

func TestWrapper_OAuthAuthorizationServerMetadata(t *testing.T) {
	testDID := did.MustParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		//	200
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, testDID).Return(true, nil)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: testDID.ID})

		require.NoError(t, err)
		assert.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, testDID)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: testDID.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: did not owned")
		assert.Nil(t, res)
	})
	t.Run("error - did does not exist", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, testDID).Return(false, vdr.ErrNotFound)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: testDID.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unable to find the DID document")
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		//500
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, testDID).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: testDID.ID})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unknown error")
		assert.Nil(t, res)
	})
}

func TestWrapper_GetWebDID(t *testing.T) {
	nutsDID := did.MustParseDID("did:nuts:123")
	webDID := did.MustParseDID("did:web:example.com:iam:123")
	publicURL := ssi.MustParseURI("https://example.com").URL
	webDIDBaseURL := publicURL.JoinPath("/iam")
	ctx := audit.TestContext()
	expectedWebDIDDoc := did.Document{
		ID: webDID,
	}
	// remarshal expectedWebDIDDoc to make sure in-memory format is the same as the one returned by the API
	data, _ := expectedWebDIDDoc.MarshalJSON()
	_ = expectedWebDIDDoc.UnmarshalJSON(data)

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().DeriveWebDIDDocument(gomock.Any(), *webDIDBaseURL, nutsDID).Return(&expectedWebDIDDoc, nil)

		response, err := test.client.GetWebDID(ctx, GetWebDIDRequestObject{nutsDID.ID})

		assert.NoError(t, err)
		assert.Equal(t, expectedWebDIDDoc, did.Document(response.(GetWebDID200JSONResponse)))
	})
	t.Run("unknown DID", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().DeriveWebDIDDocument(ctx, *webDIDBaseURL, nutsDID).Return(nil, vdr.ErrNotFound)

		response, err := test.client.GetWebDID(ctx, GetWebDIDRequestObject{nutsDID.ID})

		assert.NoError(t, err)
		assert.IsType(t, GetWebDID404Response{}, response)
	})
	t.Run("other error", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().DeriveWebDIDDocument(gomock.Any(), *webDIDBaseURL, nutsDID).Return(nil, errors.New("failed"))

		response, err := test.client.GetWebDID(ctx, GetWebDIDRequestObject{nutsDID.ID})

		assert.EqualError(t, err, "unable to resolve DID")
		assert.Nil(t, response)
	})
}

func TestWrapper_GetOAuthClientMetadata(t *testing.T) {
	did := did.MustParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, did).Return(true, nil)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: did.ID})

		require.NoError(t, err)
		assert.IsType(t, OAuthClientMetadata200JSONResponse{}, res)
	})
	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, did)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: did.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, did).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: did.ID})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "unknown error")
		assert.Nil(t, res)
	})
}
func TestWrapper_PresentationDefinition(t *testing.T) {
	webDID := did.MustParseDID("did:web:example.com:iam:123")
	ctx := audit.TestContext()
	definitionResolver := pe.DefinitionResolver{}
	_ = definitionResolver.LoadFromFile("test/presentation_definition_mapping.json")

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.authnServices.EXPECT().PresentationDefinitions().Return(&definitionResolver)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{Scope: []string{"test"}}})

		require.NoError(t, err)
		require.NotNil(t, response)
		definitions := []PresentationDefinition(response.(PresentationDefinition200JSONResponse))
		assert.Len(t, definitions, 1)
	})

	t.Run("ok - missing scope", func(t *testing.T) {
		test := newTestClient(t)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{}})

		require.NoError(t, err)
		require.NotNil(t, response)
		definitions := []PresentationDefinition(response.(PresentationDefinition200JSONResponse))
		assert.Len(t, definitions, 0)
	})

	t.Run("error - unknown scope", func(t *testing.T) {
		test := newTestClient(t)
		test.authnServices.EXPECT().PresentationDefinitions().Return(&definitionResolver)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{Scope: []string{"unknown"}}})

		assert.EqualError(t, err, "unsupported scope: unknown")
		assert.Nil(t, response)
	})
}

// statusCodeFrom returns the statuscode if err is core.HTTPStatusCodeError, or 0 if it isn't
func statusCodeFrom(err error) int {
	var SE core.HTTPStatusCodeError
	if errors.As(err, &SE) {
		return SE.StatusCode()
	}
	return 0
}

type testCtx struct {
	client        *Wrapper
	authnServices *auth.MockAuthenticationServices
	vdr           *vdr.MockVDR
	resolver      *vdr.MockDIDResolver
	relyingParty  *oauth.MockRelyingParty
}

func newTestClient(t testing.TB) *testCtx {
	publicURL, err := url.Parse("https://example.com")
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	authnServices := auth.NewMockAuthenticationServices(ctrl)
	relyingPary := oauth.NewMockRelyingParty(ctrl)
	resolver := vdr.NewMockDIDResolver(ctrl)
	vdr := vdr.NewMockVDR(ctrl)

	authnServices.EXPECT().PublicURL().Return(publicURL).AnyTimes()
	authnServices.EXPECT().RelyingParty().Return(relyingPary).AnyTimes()
	vdr.EXPECT().Resolver().Return(resolver).AnyTimes()

	return &testCtx{
		authnServices: authnServices,
		relyingParty:  relyingPary,
		resolver:      resolver,
		vdr:           vdr,
		client: &Wrapper{
			auth: authnServices,
			vdr:  vdr,
		},
	}
}
