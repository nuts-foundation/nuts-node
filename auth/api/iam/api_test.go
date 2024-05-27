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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/http/user"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	oauthServices "github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var rootWebDID = did.MustParseDID("did:web:example.com")
var webDID = did.MustParseDID("did:web:example.com:iam:123")
var verifierDID = did.MustParseDID("did:web:example.com:iam:verifier")
var verifierURL = "https://example.com/iam/verifier"

func TestWrapper_OAuthAuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		//	200
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(true, nil)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: "123"})

		require.NoError(t, err)
		assert.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
	})

	t.Run("error - DID not managed by this node", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: "123"})

		assert.Equal(t, 400, statusCodeFrom(err))
		assert.EqualError(t, err, "DID document not managed by this node")
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		//500
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{Id: "123"})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "DID resolution failed: unknown error")
		assert.Nil(t, res)
	})
}

func TestWrapper_RootOAuthAuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, rootWebDID).Return(true, nil)

		res, err := ctx.client.RootOAuthAuthorizationServerMetadata(nil, RootOAuthAuthorizationServerMetadataRequestObject{})

		require.NoError(t, err)
		assert.IsType(t, RootOAuthAuthorizationServerMetadata200JSONResponse{}, res)
		actualIssuer := res.(RootOAuthAuthorizationServerMetadata200JSONResponse).Issuer
		assert.Equal(t, "https://example.com", actualIssuer)
	})
}

func TestWrapper_GetTenantWebDID(t *testing.T) {
	const webIDPart = "123"
	ctx := audit.TestContext()
	expectedWebDIDDoc := did.Document{
		ID: webDID,
	}
	// remarshal expectedWebDIDDoc to make sure in-memory format is the same as the one returned by the API
	data, _ := json.Marshal(expectedWebDIDDoc)
	_ = expectedWebDIDDoc.UnmarshalJSON(data)

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(webDID).Return(&expectedWebDIDDoc, nil)

		response, err := test.client.GetTenantWebDID(ctx, GetTenantWebDIDRequestObject{webIDPart})

		assert.NoError(t, err)
		assert.Equal(t, expectedWebDIDDoc, did.Document(response.(GetTenantWebDID200JSONResponse)))
	})
	t.Run("unknown DID", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(webDID).Return(nil, resolver.ErrNotFound)

		response, err := test.client.GetTenantWebDID(ctx, GetTenantWebDIDRequestObject{webIDPart})

		assert.NoError(t, err)
		assert.IsType(t, GetTenantWebDID404Response{}, response)
	})
	t.Run("other error", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(webDID).Return(nil, errors.New("failed"))

		response, err := test.client.GetTenantWebDID(ctx, GetTenantWebDIDRequestObject{webIDPart})

		assert.EqualError(t, err, "unable to resolve DID")
		assert.Nil(t, response)
	})
}

func TestWrapper_GetRootWebDID(t *testing.T) {
	ctx := audit.TestContext()
	expectedWebDIDDoc := did.Document{
		ID: rootWebDID,
	}
	// remarshal expectedWebDIDDoc to make sure in-memory format is the same as the one returned by the API
	data, _ := json.Marshal(expectedWebDIDDoc)
	_ = expectedWebDIDDoc.UnmarshalJSON(data)

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(rootWebDID).Return(&expectedWebDIDDoc, nil)

		response, err := test.client.GetRootWebDID(ctx, GetRootWebDIDRequestObject{})

		assert.NoError(t, err)
		assert.Equal(t, expectedWebDIDDoc, did.Document(response.(GetRootWebDID200JSONResponse)))
	})
	t.Run("unknown DID", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(rootWebDID).Return(nil, resolver.ErrNotFound)

		response, err := test.client.GetRootWebDID(ctx, GetRootWebDIDRequestObject{})

		assert.NoError(t, err)
		assert.IsType(t, GetRootWebDID404Response{}, response)
	})
	t.Run("other error", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().ResolveManaged(rootWebDID).Return(nil, errors.New("failed"))

		response, err := test.client.GetRootWebDID(ctx, GetRootWebDIDRequestObject{})

		assert.EqualError(t, err, "unable to resolve DID")
		assert.Nil(t, response)
	})
}

func TestWrapper_GetOAuthClientMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(true, nil)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Did: webDID.String()})

		require.NoError(t, err)
		assert.IsType(t, OAuthClientMetadata200JSONResponse{}, res)
	})
	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Did: webDID.String()})

		assert.Equal(t, 400, statusCodeFrom(err))
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(false, errors.New("unknown error"))

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{Did: webDID.String()})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "DID resolution failed: unknown error")
		assert.Nil(t, res)
	})
}
func TestWrapper_PresentationDefinition(t *testing.T) {
	webDID := did.MustParseDID("did:web:example.com:iam:123")
	ctx := audit.TestContext()
	walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}
	userWalletType := pe.WalletOwnerUser

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), webDID, "example-scope").Return(walletOwnerMapping, nil)
		test.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{Scope: "example-scope"}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("ok - missing scope", func(t *testing.T) {
		test := newTestClient(t)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("ok - user wallet", func(t *testing.T) {
		walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerUser: pe.PresentationDefinition{Id: "test"}}

		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), webDID, "example-scope").Return(walletOwnerMapping, nil)
		test.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{Scope: "example-scope", WalletOwnerType: &userWalletType}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("err - unknown wallet type", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), webDID, "example-scope").Return(walletOwnerMapping, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{Scope: "example-scope", WalletOwnerType: &userWalletType}})

		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "invalid_request - no presentation definition found for 'user' wallet", err.Error())
	})

	t.Run("error - unknown scope", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), webDID, "unknown").Return(nil, policy.ErrNotFound)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{Scope: "unknown"}})

		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "invalid_scope - not found", err.Error())
	})

	t.Run("error - unknown DID", func(t *testing.T) {
		test := newTestClient(t)
		test.vdr.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{Did: webDID.String(), Params: PresentationDefinitionParams{Scope: "example-scope"}})

		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "invalid_request - DID document not managed by this node", err.Error())
	})
}

func TestWrapper_HandleAuthorizeRequest(t *testing.T) {

	t.Run("ok - response_type=code", func(t *testing.T) {
		ctx := newTestClient(t)

		// HandleAuthorizeRequest
		requestParams := oauthParameters{
			jwt.AudienceKey:                []string{verifierDID.String()},
			jwt.IssuerKey:                  holderDID.String(),
			oauth.ClientIDParam:            holderDID.String(),
			oauth.NonceParam:               "nonce",
			oauth.RedirectURIParam:         "https://example.com",
			oauth.ResponseTypeParam:        oauth.CodeResponseType,
			oauth.ScopeParam:               "test",
			oauth.StateParam:               "state",
			oauth.CodeChallengeParam:       "code_challenge",
			oauth.CodeChallengeMethodParam: "S256",
		}
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
		ctx.jar.EXPECT().Parse(gomock.Any(), verifierDID, url.Values{"key": []string{"test_value"}}).Return(requestParams, nil)

		// handleAuthorizeRequestFromHolder
		expectedURL := "https://example.com/authorize?client_id=did%3Aweb%3Aexample.com%3Aiam%3Averifier&request_uri=https://example.com/oauth2/" + verifierDID.String() + "/request.jwt/&request_uri_method=get"
		serverMetadata := oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint:      "https://example.com/authorize",
			ClientIdSchemesSupported:   []string{didClientIDScheme},
			VPFormats:                  oauth.DefaultOpenIDSupportedFormats(),
			RequireSignedRequestObject: true,
		}
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), verifierDID, "test").Return(pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderURL).Return(&serverMetadata, nil).Times(2)
		ctx.jar.EXPECT().Create(verifierDID, &holderDID, gomock.Any()).DoAndReturn(func(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest {
			req := createJarRequest(client, server, modifier)
			params := req.Claims
			// check the parameters
			assert.NotEmpty(t, params[oauth.NonceParam])
			assert.Equal(t, didClientIDScheme, params[oauth.ClientIDSchemeParam])
			assert.Equal(t, oauth.VPTokenResponseType, params[oauth.ResponseTypeParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/response", params[oauth.ResponseURIParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/oauth-client", params[oauth.ClientMetadataURIParam])
			assert.Equal(t, responseModeDirectPost, params[oauth.ResponseModeParam])
			assert.NotEmpty(t, params[oauth.StateParam])
			return req
		})

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{"key": "test_value"}),
			HandleAuthorizeRequestRequestObject{Did: verifierDID.String()})

		require.NoError(t, err)
		require.IsType(t, HandleAuthorizeRequest302Response{}, res)
		testAuthzReqRedirectURI(t, expectedURL, res.(HandleAuthorizeRequest302Response).Headers.Location)
	})
	t.Run("ok - response_type=vp_token ", func(t *testing.T) {
		ctx := newTestClient(t)
		vmId := did.DIDURL{
			DID:             verifierDID,
			Fragment:        "key",
			DecodedFragment: "key",
		}
		kid := vmId.String()
		key := cryptoNuts.NewTestKey(kid)
		didDocument := did.Document{ID: verifierDID}
		vm, _ := did.NewVerificationMethod(vmId, ssi.JsonWebKey2020, did.DID{}, key.Public())
		didDocument.AddAssertionMethod(vm)

		// HandleAuthorizeRequest
		requestParams := oauthParameters{
			oauth.ClientIDParam:           verifierDID.String(),
			oauth.ClientIDSchemeParam:     didClientIDScheme,
			oauth.ClientMetadataURIParam:  "https://example.com/.well-known/authorization-server/iam/verifier",
			oauth.NonceParam:              "nonce",
			oauth.PresentationDefUriParam: "https://example.com/oauth2/did:web:example.com:iam:verifier/presentation_definition?scope=test",
			oauth.ResponseURIParam:        "https://example.com/oauth2/did:web:example.com:iam:verifier/response",
			oauth.ResponseModeParam:       responseModeDirectPost,
			oauth.ResponseTypeParam:       oauth.VPTokenResponseType,
			oauth.ScopeParam:              "test",
			oauth.StateParam:              "state",
		}
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), holderDID).Return(true, nil)
		ctx.jar.EXPECT().Parse(gomock.Any(), holderDID, gomock.Any()).Return(requestParams, nil)

		// handleAuthorizeRequestFromVerifier
		_ = ctx.client.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...).Put("state", OAuthSession{
			// this is the state from the holder that was stored at the creation of the first authorization request to the verifier
			ClientID:     holderDID.String(),
			Scope:        "test",
			OwnDID:       &holderDID,
			ClientState:  "state",
			RedirectURI:  "https://example.com/iam/holder/cb",
			ResponseType: "code",
		})
		callCtx, _ := user.CreateTestSession(requestContext(nil), holderDID)
		clientMetadata := oauth.OAuthClientMetadata{VPFormats: oauth.DefaultOpenIDSupportedFormats()}
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		pdEndpoint := "https://example.com/oauth2/did:web:example.com:iam:verifier/presentation_definition?scope=test"
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(&pe.PresentationDefinition{}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, gomock.Any()).Return(&vc.VerifiablePresentation{}, &pe.PresentationSubmission{}, nil)
		ctx.iamClient.EXPECT().PostAuthorizationResponse(gomock.Any(), vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "https://example.com/oauth2/did:web:example.com:iam:verifier/response", "state").Return("https://example.com/iam/holder/redirect", nil)

		res, err := ctx.client.HandleAuthorizeRequest(callCtx, HandleAuthorizeRequestRequestObject{
			Did: holderDID.String(),
		})

		require.NoError(t, err)
		assert.IsType(t, HandleAuthorizeRequest302Response{}, res)
		location := res.(HandleAuthorizeRequest302Response).Headers.Location
		assert.Equal(t, location, "https://example.com/iam/holder/redirect")
	})
	t.Run("unsupported response_type", func(t *testing.T) {
		ctx := newTestClient(t)
		requestParams := oauthParameters{
			oauth.ClientIDParam:     holderDID.String(),
			oauth.ResponseTypeParam: "unsupported",
		}
		ctx.jar.EXPECT().Parse(gomock.Any(), verifierDID, gomock.Any()).Return(requestParams, nil)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{}),
			HandleAuthorizeRequestRequestObject{Did: verifierDID.String()})

		requireOAuthError(t, err, oauth.UnsupportedResponseType, "")
		assert.Nil(t, res)
	})
}

func TestWrapper_HandleTokenRequest(t *testing.T) {
	t.Run("unsupported grant type", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)

		res, err := ctx.client.HandleTokenRequest(nil, HandleTokenRequestRequestObject{
			Did: webDID.String(),
			Body: &HandleTokenRequestFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		requireOAuthError(t, err, oauth.UnsupportedGrantType, "grant_type 'unsupported' is not supported")
		assert.Nil(t, res)
	})
}

func TestWrapper_Callback(t *testing.T) {
	code := "code"
	errorCode := "error"
	errorDescription := "error description"
	state := "state"
	token := "token"

	session := OAuthSession{
		SessionID:     "token",
		OwnDID:        &holderDID,
		RedirectURI:   "https://example.com/iam/holder/cb",
		VerifierDID:   &verifierDID,
		TokenEndpoint: "https://example.com/token",
	}

	t.Run("ok - error flow", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		putState(ctx, "state", session)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				State:            &state,
				Error:            &errorCode,
				ErrorDescription: &errorDescription,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/iam/holder/cb?error=error&error_description=error+description", res.(Callback302Response).Headers.Location)
	})
	t.Run("ok - success flow", func(t *testing.T) {
		ctx := newTestClient(t)
		withDPoP := session
		withDPoP.UseDPoP = true
		putState(ctx, "state", withDPoP)
		putToken(ctx, token)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil).Times(2)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, session.TokenEndpoint, "https://example.com/oauth2/did:web:example.com:iam:123/callback", holderDID, codeVerifier, true).Return(&oauth.TokenResponse{AccessToken: "access"}, nil)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/iam/holder/cb", res.(Callback302Response).Headers.Location)

		// assert AccessToken store entry has active status
		var tokenResponse TokenResponse
		err = ctx.client.accessTokenClientStore().Get(token, &tokenResponse)
		require.NoError(t, err)
		assert.Equal(t, oauth.AccessTokenRequestStatusActive, tokenResponse.Get("status"))
		assert.Equal(t, "access", tokenResponse.AccessToken)
	})
	t.Run("ok - no DPoP", func(t *testing.T) {
		ctx := newTestClient(t)
		_ = ctx.client.oauthClientStateStore().Put(state, OAuthSession{
			OwnDID:        &holderDID,
			PKCEParams:    generatePKCEParams(),
			RedirectURI:   "https://example.com/iam/holder/cb",
			SessionID:     "token",
			UseDPoP:       false,
			VerifierDID:   &verifierDID,
			TokenEndpoint: session.TokenEndpoint,
		})
		putToken(ctx, token)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil).Times(2)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, session.TokenEndpoint, "https://example.com/oauth2/did:web:example.com:iam:123/callback", holderDID, codeVerifier, false).Return(&oauth.TokenResponse{AccessToken: "access"}, nil)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			Did: webDID.String(),
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, res)
	})
	t.Run("unknown did", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(false, nil)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			Did: webDID.String(),
		})

		assert.EqualError(t, err, "DID document not managed by this node")
		assert.Nil(t, res)
	})
}

func TestWrapper_RetrieveAccessToken(t *testing.T) {
	request := RetrieveAccessTokenRequestObject{
		SessionID: "id",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		putToken(ctx, "id")

		res, err := ctx.client.RetrieveAccessToken(nil, request)

		require.NoError(t, err)
		assert.IsType(t, RetrieveAccessToken200JSONResponse{}, res)
		assert.ErrorIs(t, ctx.client.accessTokenClientStore().Get("id", new(TokenResponse)), storage.ErrNotFound)
	})
	t.Run("error - 404 unknown sessionID", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.RetrieveAccessToken(nil, request)
		assert.ErrorIs(t, err, core.NotFoundError(""))
		assert.Nil(t, res)
	})
}

func TestWrapper_IntrospectAccessToken(t *testing.T) {
	// mvp to store access token
	ctx := newTestClient(t)
	dpopToken, _, thumbprint := newSignedTestDPoP()

	// validate all fields are there after introspection
	t.Run("error - no token provided", func(t *testing.T) {
		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: ""}})
		require.NoError(t, err)
		assert.Equal(t, res, IntrospectAccessToken200JSONResponse{})
	})
	t.Run("error - other store error", func(t *testing.T) {
		// token is invalid JSON
		require.NoError(t, ctx.client.accessTokenServerStore().Put("err", "{"))
		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "err"}})
		assert.ErrorContains(t, err, "json: cannot unmarshal")
		assert.Nil(t, res)
	})
	t.Run("error - does not exist", func(t *testing.T) {
		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "does not exist"}})
		require.NoError(t, err)
		assert.Equal(t, res, IntrospectAccessToken200JSONResponse{})
	})
	t.Run("error - expired token", func(t *testing.T) {
		token := AccessToken{Expiration: time.Now().Add(-time.Second)}
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.NoError(t, err)
		assert.Equal(t, res, IntrospectAccessToken200JSONResponse{})
	})
	t.Run("ok", func(t *testing.T) {
		token := AccessToken{Expiration: time.Now().Add(time.Second), DPoP: dpopToken}
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.NoError(t, err)
		tokenResponse, ok := res.(IntrospectAccessToken200JSONResponse)
		require.True(t, ok)
		assert.True(t, tokenResponse.Active)
	})
	t.Run("with claims from InputDescriptorConstraintIdMap", func(t *testing.T) {
		token := AccessToken{
			Expiration: time.Now().Add(time.Second),
			InputDescriptorConstraintIdMap: map[string]any{
				"family_name": "Doe",
			},
		}
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.NoError(t, err)
		tokenResponse, ok := res.(IntrospectAccessToken200JSONResponse)
		require.True(t, ok)
		assert.Equal(t, "Doe", tokenResponse.AdditionalProperties["family_name"])
	})
	t.Run("InputDescriptorConstraintIdMap contains reserved claim", func(t *testing.T) {
		token := AccessToken{
			Expiration: time.Now().Add(time.Second),
			InputDescriptorConstraintIdMap: map[string]any{
				"iss": "value",
			},
		}
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.EqualError(t, err, "IntrospectAccessToken: InputDescriptorConstraintIdMap contains reserved claim name: iss")
		require.Nil(t, res)
	})

	t.Run(" ok - s2s flow", func(t *testing.T) {
		// TODO: this should be an integration test to make sure all fields are set
		credential, err := vc.ParseVerifiableCredential(jsonld.TestOrganizationCredential)
		require.NoError(t, err)
		presentation := vc.VerifiablePresentation{
			VerifiableCredential: []vc.VerifiableCredential{*credential},
		}
		tNow := time.Now()
		presentationSubmissions := map[string]pe.PresentationSubmission{"test": {}}
		presentationDefinitions := RequiredPresentationDefinitions{
			pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"},
		}
		token := AccessToken{
			DPoP:                           dpopToken,
			Token:                          "token",
			Issuer:                         "resource-owner",
			ClientId:                       "client",
			IssuedAt:                       tNow,
			Expiration:                     tNow.Add(time.Minute),
			Scope:                          "test",
			InputDescriptorConstraintIdMap: map[string]any{"key": "value"},
			VPToken:                        []VerifiablePresentation{presentation},
			PresentationSubmissions:        presentationSubmissions,
			PresentationDefinitions:        presentationDefinitions,
		}

		require.NoError(t, ctx.client.accessTokenServerStore().Put(token.Token, token))
		expectedResponse, err := json.Marshal(IntrospectAccessToken200JSONResponse{
			Active:                  true,
			ClientId:                ptrTo("client"),
			Cnf:                     &Cnf{Jkt: thumbprint},
			Exp:                     ptrTo(int(tNow.Add(time.Minute).Unix())),
			Iat:                     ptrTo(int(tNow.Unix())),
			Iss:                     ptrTo("resource-owner"),
			Scope:                   ptrTo("test"),
			Sub:                     ptrTo("resource-owner"),
			Vps:                     &[]VerifiablePresentation{presentation},
			PresentationSubmissions: ptrTo(presentationSubmissions),
			PresentationDefinitions: ptrTo(presentationDefinitions),
			AdditionalProperties:    map[string]interface{}{"key": "value"},
		})
		require.NoError(t, err)

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: token.Token}})

		require.NoError(t, err)
		tokenResponse, err := json.Marshal(res)
		assert.NoError(t, err)
		assert.JSONEq(t, string(expectedResponse), string(tokenResponse))
	})
}

func TestWrapper_Routes(t *testing.T) {
	t.Run("it registers handlers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		router := core.NewMockEchoRouter(ctrl)

		router.EXPECT().Use(gomock.Any()).AnyTimes()
		router.EXPECT().GET(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		router.EXPECT().POST(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		(&Wrapper{
			storageEngine: storage.NewTestStorageEngine(t),
		}).Routes(router)
	})
	t.Run("cache middleware URLs match registered paths", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		router := core.NewMockEchoRouter(ctrl)

		var registeredPaths []string
		router.EXPECT().GET(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(path string, _ echo.HandlerFunc, _ ...echo.MiddlewareFunc) *echo.Route {
			registeredPaths = append(registeredPaths, path)
			return nil
		}).AnyTimes()
		router.EXPECT().POST(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(path string, _ echo.HandlerFunc, _ ...echo.MiddlewareFunc) *echo.Route {
			registeredPaths = append(registeredPaths, path)
			return nil
		}).AnyTimes()
		router.EXPECT().Use(gomock.Any()).AnyTimes()
		(&Wrapper{}).Routes(router)

		// Check that all cache-control max-age paths are actual paths
		for _, path := range cacheControlMaxAgeURLs {
			assert.Contains(t, registeredPaths, path)
		}
		// Check that all cache-control no-cache paths are actual paths
		for _, path := range cacheControlNoCacheURLs {
			assert.Contains(t, registeredPaths, path)
		}
	})
}

func TestWrapper_middleware(t *testing.T) {
	server := echo.New()
	ctrl := gomock.NewController(t)
	authService := auth.NewMockAuthenticationServices(ctrl)

	t.Run("OAuth2 error handling", func(t *testing.T) {
		var handler strictServerCallCapturer
		t.Run("OAuth2 path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/oauth2/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.strictMiddleware(ctx, nil, "Test", handler.handle)

			assert.IsType(t, &oauth.Oauth2ErrorWriter{}, ctx.Get(core.ErrorWriterContextKey))
		})
		t.Run("other path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/internal/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.strictMiddleware(ctx, nil, "Test", handler.handle)

			assert.Nil(t, ctx.Get(core.ErrorWriterContextKey))
		})
	})

}

func TestWrapper_toOwnedDID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(true, nil)

		_, err := ctx.client.toOwnedDID(nil, webDID.String())

		assert.NoError(t, err)
	})
	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID)

		_, err := ctx.client.toOwnedDID(nil, webDID.String())

		assert.EqualError(t, err, "DID document not managed by this node")
	})
	t.Run("DID does not exist (functional resolver error)", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(false, resolver.ErrNotFound)

		_, err := ctx.client.toOwnedDID(nil, webDID.String())

		assert.EqualError(t, err, "invalid issuer DID: unable to find the DID document")
	})
	t.Run("other resolver error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, webDID).Return(false, errors.New("unknown error"))

		_, err := ctx.client.toOwnedDID(nil, webDID.String())

		assert.EqualError(t, err, "DID resolution failed: unknown error")
	})
}

func TestWrapper_RequestServiceAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")
	body := &RequestServiceAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second"}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second", true).Return(&oauth.TokenResponse{}, nil)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.NoError(t, err)
	})
	t.Run("ok - no DPoP", func(t *testing.T) {
		ctx := newTestClient(t)
		tokenTypeBearer := ServiceAccessTokenRequestTokenType("bearer")
		body := &RequestServiceAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", TokenType: &tokenTypeBearer}
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second", false).Return(&oauth.TokenResponse{}, nil)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.NoError(t, err)
	})
	t.Run("error - DID not owned", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(false, nil)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "DID document not managed by this node")
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: "invalid", Body: body})

		require.EqualError(t, err, "invalid DID: invalid DID")
	})
	t.Run("error - invalid verifier did", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		body := &RequestServiceAccessTokenJSONRequestBody{Verifier: "invalid"}

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "invalid verifier: invalid DID")
	})
	t.Run("error - verifier error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second", true).Return(nil, core.Error(http.StatusPreconditionFailed, "no matching credentials"))

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "no matching credentials")
	})
}

func TestWrapper_RequestUserAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")
	tokenType := UserAccessTokenRequestTokenType("dpop")
	userDetails := UserDetails{
		Id:   "test",
		Name: "Titus Tester",
		Role: "Test Manager",
	}
	redirectURI := "https://test.test/oauth2/" + walletDID.String() + "/cb"
	body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", PreauthorizedUser: &userDetails, RedirectUri: redirectURI, TokenType: &tokenType}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)

		response, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		// assert token
		require.NoError(t, err)
		redirectResponse, ok := response.(RequestUserAccessToken200JSONResponse)
		assert.True(t, ok)
		assert.Contains(t, redirectResponse.RedirectUri, "https://test.test/oauth2/"+walletDID.String()+"/user?token=")

		// assert session
		var target RedirectSession
		redirectURI, _ := url.Parse(redirectResponse.RedirectUri)
		err = ctx.client.userRedirectStore().Get(redirectURI.Query().Get("token"), &target)
		require.NoError(t, err)
		assert.Equal(t, walletDID, target.OwnDID)
		require.NotNil(t, target.AccessTokenRequest)
		require.NotNil(t, target.AccessTokenRequest.Body.TokenType)
		assert.Equal(t, tokenType, *target.AccessTokenRequest.Body.TokenType)

		// assert flow
		var tokenResponse TokenResponse
		require.NotNil(t, redirectResponse.SessionId)
		err = ctx.client.accessTokenClientStore().Get(redirectResponse.SessionId, &tokenResponse)
		assert.Equal(t, oauth.AccessTokenRequestStatusPending, tokenResponse.Get("status"))
	})
	t.Run("preauthorized_user", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).AnyTimes().Return(true, nil)
		t.Run("error - missing preauthorized_user", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", RedirectUri: redirectURI}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: walletDID.String(), Body: body})

			require.EqualError(t, err, "missing preauthorized_user")
		})
		t.Run("error - missing preauthorized_user.id", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", PreauthorizedUser: &UserDetails{Name: "Titus Tester"}, RedirectUri: redirectURI}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: walletDID.String(), Body: body})

			require.EqualError(t, err, "missing preauthorized_user.id")
		})
		t.Run("error - missing preauthorized_user.name", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", PreauthorizedUser: &UserDetails{Id: "test"}, RedirectUri: redirectURI}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: walletDID.String(), Body: body})

			require.EqualError(t, err, "missing preauthorized_user.name")
		})
		t.Run("error - missing preauthorized_user.role", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", PreauthorizedUser: &UserDetails{Id: "test", Name: "Titus Tester"}, RedirectUri: redirectURI}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: walletDID.String(), Body: body})

			require.EqualError(t, err, "missing preauthorized_user.role")
		})
	})

	t.Run("error - invalid DID", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{Did: "invalid", Body: body})

		require.EqualError(t, err, "invalid DID: invalid DID")
	})
}

func TestWrapper_StatusList(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		page := 1
		id := "123"
		issuerDID := did.MustParseDID("did:web:example.com:iam:" + id)
		slCred := VerifiableCredential{Issuer: ssi.MustParseURI(issuerDID.String())}
		ctx.vcIssuer.EXPECT().StatusList(nil, issuerDID, page).Return(&slCred, nil)

		res, err := ctx.client.StatusList(nil, StatusListRequestObject{
			Did:  issuerDID.String(),
			Page: page,
		})

		assert.NoError(t, err)
		assert.Equal(t, StatusList200JSONResponse(slCred), res)
	})
	t.Run("error - not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vcIssuer.EXPECT().StatusList(nil, gomock.Any(), gomock.Any()).Return(nil, types.ErrNotFound)

		res, err := ctx.client.StatusList(nil, StatusListRequestObject{Did: webDID.String()})

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Nil(t, res)
	})
}

func TestWrapper_GetRequestJWT(t *testing.T) {
	cont := context.Background()
	requestID := "thisID"
	expectedToken := "validToken"
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(webDID, &holderDID, func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return(expectedToken, nil)

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{Did: webDID.String(), Id: requestID})

		assert.NoError(t, err)
		assert.Equal(t, RequestJWTByGet200ApplicationoauthAuthzReqJwtResponse{
			Body:          bytes.NewReader([]byte(expectedToken)),
			ContentLength: 10,
		}, response)
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - not found", func(t *testing.T) {
		ctx := newTestClient(t)

		response, err := ctx.client.RequestJWTByGet(nil, RequestJWTByGetRequestObject{Id: "unknownID"})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - request object not found")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - clientID does not match request", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(webDID, &holderDID, func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{Did: holderDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - client_id does not match request")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - wrong request_uri_method used", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(webDID, &holderDID, func(claims map[string]string) {})
		ro.RequestURIMethod = "post"
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{Did: webDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - wrong 'request_uri_method' authorization server or wallet probably does not support 'request_uri_method' - used request_uri_method 'get' on a 'post' request_uri")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - signing failed", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(webDID, &holderDID, func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return("", errors.New("fail"))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{Did: webDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "server_error - failed to sign authorization Request Object: fail - unable to create Request Object")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
}

func TestWrapper_PostRequestJWT(t *testing.T) {
	cont := context.Background()
	requestID := "thisID"
	expectedToken := "validToken"
	newReqObj := func(issuer, nonce string) jarRequest {
		ro := jar{}.Create(webDID, nil, func(claims map[string]string) {})
		if issuer != "" {
			ro.Claims[jwt.AudienceKey] = issuer
		}
		if nonce != "" {
			ro.Claims[oauth.WalletNonceParam] = nonce
		}
		return ro
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := newReqObj("https://self-issued.me/v2", "")
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return(expectedToken, nil)

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{Did: webDID.String(), Id: requestID})

		assert.NoError(t, err)
		assert.Equal(t, RequestJWTByPost200ApplicationoauthAuthzReqJwtResponse{
			Body:          bytes.NewReader([]byte(expectedToken)),
			ContentLength: 10,
		}, response)
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("ok - with metadata and nonce", func(t *testing.T) {
		wallet_nonce := "wallet_nonce"
		ctx := newTestClient(t)
		ro := newReqObj("mario", wallet_nonce)
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return(expectedToken, nil)
		body := RequestJWTByPostFormdataRequestBody(RequestJWTByPostFormdataBody{
			WalletMetadata: &oauth.AuthorizationServerMetadata{Issuer: "mario"},
			WalletNonce:    &wallet_nonce,
		})

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{Did: webDID.String(), Id: requestID, Body: &body})

		assert.NoError(t, err)
		assert.Equal(t, RequestJWTByPost200ApplicationoauthAuthzReqJwtResponse{
			Body:          bytes.NewReader([]byte(expectedToken)),
			ContentLength: 10,
		}, response)
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - not found", func(t *testing.T) {
		ctx := newTestClient(t)

		response, err := ctx.client.RequestJWTByPost(nil, RequestJWTByPostRequestObject{Id: "unknownID"})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - request object not found")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - clientID does not match request", func(t *testing.T) {
		ctx := newTestClient(t)
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, newReqObj("", "")))

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{Did: holderDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - client_id does not match request")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - wrong request_uri_method used", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := newReqObj("", "")
		ro.RequestURIMethod = "get"
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{Did: webDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - used request_uri_method 'post' on a 'get' request_uri")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - signing failed", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := newReqObj("https://self-issued.me/v2", "")
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return("", errors.New("fail"))

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{Did: webDID.String(), Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "server_error - failed to sign authorization Request Object: fail - unable to create Request Object")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
}

func TestWrapper_CreateAuthorizationRequest(t *testing.T) {
	clientDID := did.MustParseDID("did:web:client.test:iam:123")
	serverDID := did.MustParseDID("did:web:server.test:iam:123")
	var serverURL = "https://server.test/iam/123"
	modifier := func(values map[string]string) {
		values["custom"] = "value"
	}
	serverMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:      "https://server.test/authorize",
		RequireSignedRequestObject: true,
	}
	t.Run("ok - RequireSignedRequestObject=true", func(t *testing.T) {
		expectedRedirect := "https://server.test/authorize?client_id=did%3Aweb%3Aclient.test%3Aiam%3A123&request_uri=https://client.test/oauth2/&request_uri_method=custom"
		var expectedJarReq jarRequest
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), serverURL).Return(&serverMetadata, nil)
		ctx.jar.EXPECT().Create(clientDID, &serverDID, gomock.Any()).DoAndReturn(func(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest {
			expectedJarReq = createJarRequest(client, server, modifier)
			expectedJarReq.RequestURIMethod = "custom"
			assert.Equal(t, "value", expectedJarReq.Claims.get("custom"))
			return expectedJarReq
		})

		redirectURL, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, &serverDID, modifier)

		// return
		assert.NoError(t, err)
		testAuthzReqRedirectURI(t, expectedRedirect, redirectURL.String())

		// storage
		requestURIparts := strings.Split(redirectURL.Query().Get(oauth.RequestURIParam), "/")
		requestURIID := requestURIparts[len(requestURIparts)-1]
		var jarReq jarRequest
		require.NoError(t, ctx.client.authzRequestObjectStore().Get(requestURIID, &jarReq))
		assert.Equal(t, expectedJarReq, jarReq)
	})
	t.Run("ok - no server -> RequireSignedRequestObject=false", func(t *testing.T) {
		var expectedJarReq jarRequest
		ctx := newTestClient(t)
		ctx.jar.EXPECT().Create(clientDID, nil, gomock.Any()).DoAndReturn(func(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest {
			expectedJarReq = createJarRequest(client, server, modifier)
			assert.Equal(t, "value", expectedJarReq.Claims.get("custom"))
			return expectedJarReq
		})

		redirectURL, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, nil, modifier)

		assert.NoError(t, err)
		assert.Equal(t, "value", redirectURL.Query().Get("custom"))
		assert.Equal(t, clientDID.String(), redirectURL.Query().Get(oauth.ClientIDParam))
		assert.Equal(t, "post", redirectURL.Query().Get(oauth.RequestURIMethodParam))
		assert.NotEmpty(t, redirectURL.Query().Get(oauth.RequestURIParam))
	})
	t.Run("error - missing authorization endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), serverURL).Return(&oauth.AuthorizationServerMetadata{}, nil)

		_, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, &serverDID, modifier)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "no authorization endpoint found in metadata for")
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), serverURL).Return(nil, assert.AnError)

		_, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, &serverDID, modifier)

		assert.Error(t, err)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), serverURL).Return(&oauth.AuthorizationServerMetadata{AuthorizationEndpoint: ":"}, nil)

		_, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, &serverDID, modifier)

		assert.ErrorContains(t, err, "failed to parse authorization endpoint URL")
	})
	t.Run("error - not a did:web", func(t *testing.T) {
		ctx := newTestClient(t)
		didNuts := did.MustParseDID("did:nuts:123")

		_, err := ctx.client.createAuthorizationRequest(context.Background(), clientDID, &didNuts, modifier)

		assert.ErrorContains(t, err, "unsupported DID method: nuts")
	})
}

func Test_createOAuth2BaseURL(t *testing.T) {
	t.Run("no endpoint", func(t *testing.T) {
		webDID := did.MustParseDID("did:web:example.com:iam:holder")
		actual, err := createOAuth2BaseURL(webDID)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:holder", actual.String())
	})
	t.Run("ok", func(t *testing.T) {
		webDID := did.MustParseDID("did:web:example.com:iam:holder")
		actual, err := createOAuth2BaseURL(webDID)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:holder", actual.String())
	})
	t.Run("did:web with port", func(t *testing.T) {
		const didAsString = "did:web:example.com%3A8080:iam:holder"
		webDID := did.MustParseDID(didAsString)

		actual, err := createOAuth2BaseURL(webDID)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, "https://example.com:8080/oauth2/did:web:example.com%3A8080:iam:holder", actual.String())
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		_, err := createOAuth2BaseURL(did.DID{})

		require.Error(t, err)
		assert.EqualError(t, err, "failed to convert DID to URL: URL does not represent a Web DID\nunsupported DID method: ")
	})
}

// testAuthzReqRedirectURI compares to expectedRedirectURI and actualRedirectURI
// 'request_uri' is checked for presence,
// and if expectedRedirectURI contains a 'request_uri' it will do a partial match on URL decoded actual value
func testAuthzReqRedirectURI(t testing.TB, expectedRedirectURI, actualRedirectURI string) {
	stripRequestURI := func(uri string) (string, string) {
		u, err := url.Parse(uri)
		require.NoError(t, err)
		q := u.Query()
		requestURI := q.Get(oauth.RequestURIParam)
		q.Set(oauth.RequestURIParam, "<IGNORED>")
		u.RawQuery = q.Encode()
		return u.String(), requestURI
	}
	expected, expectedReqURIPartial := stripRequestURI(expectedRedirectURI)
	actual, actualReqURI := stripRequestURI(actualRedirectURI)
	assert.Equal(t, expected, actual)
	assert.NotEmpty(t, actualReqURI)
	assert.Contains(t, actualReqURI, expectedReqURIPartial) // both are URL decoded
}

func createIssuerCredential(issuerDID did.DID, holderDID did.DID) *vc.VerifiableCredential {
	vmId := did.DIDURL{
		DID:             issuerDID,
		Fragment:        "key",
		DecodedFragment: "key",
	}
	kid := vmId.String()
	key := cryptoNuts.NewTestKey(kid)
	credType := ssi.MustParseURI("ExampleType")

	captureFn := func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		hdrs := jws.NewHeaders()
		for key, val := range headers {
			hdrs.Set(key, val)
		}
		request := jwt.New()
		for key, val := range claims {
			request.Set(key, val)
		}
		sign, err := jwt.Sign(request, jwt.WithKey(jwa.ES256, key.Private(), jws.WithProtectedHeaders(hdrs)))
		return string(sign), err
	}

	template := VerifiableCredential{
		Issuer:            issuerDID.URI(),
		Context:           []ssi.URI{credential.NutsV1ContextURI},
		Type:              []ssi.URI{credType},
		CredentialSubject: []interface{}{map[string]interface{}{"id": holderDID.String()}},
		IssuanceDate:      time.Now(),
	}
	verifiableCredential, _ := vc.CreateJWTVerifiableCredential(nil, template, captureFn)
	return verifiableCredential
}

type strictServerCallCapturer bool

func (s *strictServerCallCapturer) handle(_ echo.Context, _ interface{}) (response interface{}, err error) {
	*s = true
	return nil, nil
}

func putToken(ctx *testCtx, token string) {
	_ = ctx.client.accessTokenClientStore().Put(token, TokenResponse{AccessToken: "token"})
}

// OG pointer function. Returns a pointer to any input.
func ptrTo[T any](v T) *T {
	return &v
}

func requireOAuthError(t *testing.T, err error, errorCode oauth.ErrorCode, errorDescription string) {
	var oauthErr oauth.OAuth2Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, errorCode, oauthErr.Code)
	assert.Equal(t, errorDescription, oauthErr.Description)
}

func requestContext(queryParams map[string]interface{}, httpRequestFn ...func(header *http.Request)) context.Context {
	vals := url.Values{}
	for key, value := range queryParams {
		switch t := value.(type) {
		case string:
			vals.Add(key, t)
		case []string:
			for _, v := range t {
				vals.Add(key, v)
			}
		default:
			panic(fmt.Sprintf("unsupported type %T", t))
		}
	}
	httpRequest := &http.Request{
		URL: &url.URL{
			RawQuery: vals.Encode(),
		},
	}
	for _, fn := range httpRequestFn {
		fn(httpRequest)
	}
	return context.WithValue(audit.TestContext(), httpRequestContextKey{}, httpRequest)
}

// statusCodeFrom returns the statuscode for the given error
func statusCodeFrom(err error) int {
	code := Wrapper{}.ResolveStatusCode(err)
	if code == 0 {
		return 500
	}
	return code
}

type testCtx struct {
	authnServices *auth.MockAuthenticationServices
	ctrl          *gomock.Controller
	client        *Wrapper
	iamClient     *iam.MockClient
	jwtSigner     *cryptoNuts.MockJWTSigner
	keyResolver   *resolver.MockKeyResolver
	policy        *policy.MockPDPBackend
	resolver      *resolver.MockDIDResolver
	relyingParty  *oauthServices.MockRelyingParty
	vcr           *vcr.MockVCR
	vdr           *vdr.MockVDR
	vcIssuer      *issuer.MockIssuer
	vcVerifier    *verifier.MockVerifier
	wallet        *holder.MockWallet
	jar           *MockJAR
}

func newTestClient(t testing.TB) *testCtx {
	publicURL, err := url.Parse("https://example.com")
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	storageEngine := storage.NewTestStorageEngine(t)
	authnServices := auth.NewMockAuthenticationServices(ctrl)
	policyInstance := policy.NewMockPDPBackend(ctrl)
	mockResolver := resolver.NewMockDIDResolver(ctrl)
	relyingPary := oauthServices.NewMockRelyingParty(ctrl)
	vcIssuer := issuer.NewMockIssuer(ctrl)
	vcVerifier := verifier.NewMockVerifier(ctrl)
	iamClient := iam.NewMockClient(ctrl)
	mockVDR := vdr.NewMockVDR(ctrl)
	mockVCR := vcr.NewMockVCR(ctrl)
	mockWallet := holder.NewMockWallet(ctrl)
	jwtSigner := cryptoNuts.NewMockJWTSigner(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	mockJAR := NewMockJAR(ctrl)

	authnServices.EXPECT().PublicURL().Return(publicURL).AnyTimes()
	authnServices.EXPECT().RelyingParty().Return(relyingPary).AnyTimes()
	mockVCR.EXPECT().Issuer().Return(vcIssuer).AnyTimes()
	mockVCR.EXPECT().Verifier().Return(vcVerifier).AnyTimes()
	mockVCR.EXPECT().Wallet().Return(mockWallet).AnyTimes()
	authnServices.EXPECT().IAMClient().Return(iamClient).AnyTimes()
	mockVDR.EXPECT().Resolver().Return(mockResolver).AnyTimes()

	return &testCtx{
		ctrl:          ctrl,
		authnServices: authnServices,
		policy:        policyInstance,
		relyingParty:  relyingPary,
		vcIssuer:      vcIssuer,
		vcVerifier:    vcVerifier,
		resolver:      mockResolver,
		vdr:           mockVDR,
		iamClient:     iamClient,
		vcr:           mockVCR,
		wallet:        mockWallet,
		keyResolver:   keyResolver,
		jwtSigner:     jwtSigner,
		jar:           mockJAR,
		client: &Wrapper{
			auth:          authnServices,
			vdr:           mockVDR,
			vcr:           mockVCR,
			storageEngine: storageEngine,
			policyBackend: policyInstance,
			keyResolver:   keyResolver,
			jwtSigner:     jwtSigner,
			jar:           mockJAR,
		},
	}
}
