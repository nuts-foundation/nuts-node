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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var nutsDID = did.MustParseDID("did:nuts:123")

func TestWrapper_OAuthAuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		//	200
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID).Return(true, nil)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: nutsDID.ID})

		require.NoError(t, err)
		assert.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: nutsDID.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: did not owned")
		assert.Nil(t, res)
	})
	t.Run("error - did does not exist", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID).Return(false, resolver.ErrNotFound)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: nutsDID.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unable to find the DID document")
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		//500
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: nutsDID.ID})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unknown error")
		assert.Nil(t, res)
	})
}

func TestWrapper_GetWebDID(t *testing.T) {
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
		test.vdr.EXPECT().DeriveWebDIDDocument(ctx, *webDIDBaseURL, nutsDID).Return(nil, resolver.ErrNotFound)

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
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID).Return(true, nil)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: nutsDID.ID})

		require.NoError(t, err)
		assert.IsType(t, OAuthClientMetadata200JSONResponse{}, res)
	})
	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: nutsDID.ID})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, nutsDID).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Id: nutsDID.ID})

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

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{Scope: "test"}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("ok - missing scope", func(t *testing.T) {
		test := newTestClient(t)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("error - unknown scope", func(t *testing.T) {
		test := newTestClient(t)
		test.authnServices.EXPECT().PresentationDefinitions().Return(&definitionResolver)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.ID, Params: PresentationDefinitionParams{Scope: "unknown"}})

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, InvalidScope, (response.(PresentationDefinition400JSONResponse)).Code)
	})
}

func TestWrapper_HandleAuthorizeRequest(t *testing.T) {
	t.Run("missing redirect_uri", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]string{}), HandleAuthorizeRequestRequestObject{
			Id: nutsDID.String(),
		})

		requireOAuthError(t, err, InvalidRequest, "redirect_uri is required")
		assert.Nil(t, res)
	})
	t.Run("unsupported response type", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]string{
			"redirect_uri":  "https://example.com",
			"response_type": "unsupported",
		}), HandleAuthorizeRequestRequestObject{
			Id: nutsDID.String(),
		})

		requireOAuthError(t, err, UnsupportedResponseType, "")
		assert.Nil(t, res)
	})
}

func TestWrapper_HandleTokenRequest(t *testing.T) {
	t.Run("unsupported grant type", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.HandleTokenRequest(nil, HandleTokenRequestRequestObject{
			Id: nutsDID.String(),
			Body: &HandleTokenRequestFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		requireOAuthError(t, err, UnsupportedGrantType, "")
		assert.Nil(t, res)
	})
}

func requireOAuthError(t *testing.T, err error, errorCode ErrorCode, errorDescription string) {
	var oauthErr OAuth2Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, errorCode, oauthErr.Code)
	assert.Equal(t, errorDescription, oauthErr.Description)
}

func requestContext(queryParams map[string]string) context.Context {
	vals := url.Values{}
	for key, value := range queryParams {
		vals.Add(key, value)
	}
	httpRequest := &http.Request{
		URL: &url.URL{
			RawQuery: vals.Encode(),
		},
	}
	return context.WithValue(audit.TestContext(), httpRequestContextKey, httpRequest)
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
	resolver      *resolver.MockDIDResolver
}

func newTestClient(t testing.TB) *testCtx {
	publicURL, err := url.Parse("https://example.com")
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	storageEngine := storage.NewTestStorageEngine(t)
	authnServices := auth.NewMockAuthenticationServices(ctrl)
	authnServices.EXPECT().PublicURL().Return(publicURL).AnyTimes()
	resolver := resolver.NewMockDIDResolver(ctrl)
	vdr := vdr.NewMockVDR(ctrl)
	vdr.EXPECT().Resolver().Return(resolver).AnyTimes()

	return &testCtx{
		authnServices: authnServices,
		resolver:      resolver,
		vdr:           vdr,
		client: &Wrapper{
			auth:          authnServices,
			vdr:           vdr,
			storageEngine: storageEngine,
		},
	}
}

func TestWrapper_Routes(t *testing.T) {
	ctrl := gomock.NewController(t)
	router := core.NewMockEchoRouter(ctrl)

	router.EXPECT().GET(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	router.EXPECT().POST(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	Wrapper{}.Routes(router)
}

func TestWrapper_middleware(t *testing.T) {
	server := echo.New()
	ctrl := gomock.NewController(t)
	authService := auth.NewMockAuthenticationServices(ctrl)
	authService.EXPECT().V2APIEnabled().Return(true).AnyTimes()

	t.Run("API enabling", func(t *testing.T) {
		t.Run("enabled", func(t *testing.T) {
			var called strictServerCallCapturer

			ctx := server.NewContext(httptest.NewRequest("GET", "/iam/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", called.handle)

			assert.True(t, bool(called))
		})
		t.Run("disabled", func(t *testing.T) {
			var called strictServerCallCapturer

			authService := auth.NewMockAuthenticationServices(ctrl)
			authService.EXPECT().V2APIEnabled().Return(false).AnyTimes()

			ctx := server.NewContext(httptest.NewRequest("GET", "/iam/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", called.handle)

			assert.False(t, bool(called))
		})
	})

	t.Run("OAuth2 error handling", func(t *testing.T) {
		var handler strictServerCallCapturer
		t.Run("OAuth2 path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/iam/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", handler.handle)

			assert.IsType(t, &oauth2ErrorWriter{}, ctx.Get(core.ErrorWriterContextKey))
		})
		t.Run("other path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/internal/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", handler.handle)

			assert.Nil(t, ctx.Get(core.ErrorWriterContextKey))
		})
	})

}

type strictServerCallCapturer bool

func (s *strictServerCallCapturer) handle(ctx echo.Context, request interface{}) (response interface{}, err error) {
	*s = true
	return nil, nil
}
