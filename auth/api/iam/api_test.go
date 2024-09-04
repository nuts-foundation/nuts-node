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
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	test2 "github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/http/user"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"io"
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

var verifierDID = did.MustParseDID("did:web:example.com:iam:verifier")
var verifierSubject = "verifier"
var verifierURL = test.MustParseURL("https://example.com/oauth2/verifier")
var verifierClientID = verifierURL.String()

var holderSubjectID = "holder"

const unknownSubjectID = "unknown"

func TestWrapper_OAuthAuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		//	200
		ctx := newTestClient(t)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{SubjectID: verifierSubject})

		require.NoError(t, err)
		assert.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
		assert.NotEmpty(t, res.(OAuthAuthorizationServerMetadata200JSONResponse).AuthorizationEndpoint)
	})
	t.Run("authorization endpoint disabled", func(t *testing.T) {
		ctx := newCustomTestClient(t, verifierURL, false)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{SubjectID: verifierSubject})

		require.NoError(t, err)
		assert.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
		assert.Empty(t, res.(OAuthAuthorizationServerMetadata200JSONResponse).AuthorizationEndpoint)
	})
	t.Run("base URL (prepended before /iam)", func(t *testing.T) {
		//	200
		baseURL := test.MustParseURL("https://example.com/base")
		ctx := newCustomTestClient(t, baseURL, false)

		res, err := ctx.client.OAuthAuthorizationServerMetadata(nil, OAuthAuthorizationServerMetadataRequestObject{SubjectID: verifierSubject})

		require.NoError(t, err)
		require.IsType(t, OAuthAuthorizationServerMetadata200JSONResponse{}, res)
		md := res.(OAuthAuthorizationServerMetadata200JSONResponse)
		assert.Equal(t, "https://example.com/base/oauth2/verifier", md.Issuer)
		assert.Equal(t, "https://example.com/base/oauth2/verifier/presentation_definition", md.PresentationDefinitionEndpoint)
	})
}

func TestWrapper_GetOAuthClientMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.OAuthClientMetadata(nil, OAuthClientMetadataRequestObject{SubjectID: holderSubjectID})

		require.NoError(t, err)
		assert.IsType(t, OAuthClientMetadata200JSONResponse{}, res)
	})
}

func TestWrapper_OpenIDConfiguration(t *testing.T) {
	testKey := test2.GenerateECKey()
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.keyResolver.EXPECT().ResolveKey(verifierDID, nil, resolver.AssertionMethod).Return("kid", testKey.Public(), nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, claims interface{}, headers interface{}, kid interface{}) (string, error) {
			asMap := claims.(map[string]interface{})
			assert.Equal(t, "https://example.com/oauth2/verifier", asMap["iss"])
			assert.Len(t, asMap["jwks"], 1)
			return "token", nil
		})

		res, err := ctx.client.OpenIDConfiguration(nil, OpenIDConfigurationRequestObject{SubjectID: verifierSubject})

		require.NoError(t, err)
		assert.IsType(t, OpenIDConfiguration200ApplicationentityStatementJwtResponse{}, res)
		successResponse := res.(OpenIDConfiguration200ApplicationentityStatementJwtResponse)
		bodyBytes, err := io.ReadAll(successResponse.Body)
		require.NoError(t, err)
		assert.Equal(t, "token", string(bodyBytes))
	})
	t.Run("error - subject does not exist", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.OpenIDConfiguration(nil, OpenIDConfigurationRequestObject{SubjectID: unknownSubjectID})

		requireOAuthError(t, err, oauth.InvalidRequest, "subject not found")
		assert.Nil(t, res)
	})
	t.Run("error - subject list DIDs returns error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), "error").Return(nil, assert.AnError)

		res, err := ctx.client.OpenIDConfiguration(nil, OpenIDConfigurationRequestObject{SubjectID: "error"})

		requireOAuthError(t, err, oauth.ServerError, "")
		assert.Nil(t, res)
	})
	t.Run("error - key resolution error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.keyResolver.EXPECT().ResolveKey(verifierDID, nil, resolver.AssertionMethod).Return("", nil, assert.AnError)

		res, err := ctx.client.OpenIDConfiguration(nil, OpenIDConfigurationRequestObject{SubjectID: verifierSubject})

		requireOAuthError(t, err, oauth.ServerError, "")
		assert.Nil(t, res)
	})
	t.Run("error - signing error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.keyResolver.EXPECT().ResolveKey(verifierDID, nil, resolver.AssertionMethod).Return("kid", testKey.Public(), nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", assert.AnError)

		res, err := ctx.client.OpenIDConfiguration(nil, OpenIDConfigurationRequestObject{SubjectID: verifierSubject})

		requireOAuthError(t, err, oauth.ServerError, "")
		assert.Nil(t, res)
	})
}

func TestWrapper_PresentationDefinition(t *testing.T) {
	ctx := audit.TestContext()
	walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}
	userWalletType := pe.WalletOwnerUser

	t.Run("ok", func(t *testing.T) {
		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), "example-scope").Return(walletOwnerMapping, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{SubjectID: verifierSubject, Params: PresentationDefinitionParams{Scope: "example-scope"}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("ok - missing scope", func(t *testing.T) {
		test := newTestClient(t)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{SubjectID: verifierSubject, Params: PresentationDefinitionParams{}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("ok - user wallet", func(t *testing.T) {
		walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerUser: pe.PresentationDefinition{Id: "test"}}

		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), "example-scope").Return(walletOwnerMapping, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{SubjectID: verifierSubject, Params: PresentationDefinitionParams{Scope: "example-scope", WalletOwnerType: &userWalletType}})

		require.NoError(t, err)
		require.NotNil(t, response)
		_, ok := response.(PresentationDefinition200JSONResponse)
		assert.True(t, ok)
	})

	t.Run("err - unknown wallet type", func(t *testing.T) {
		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), "example-scope").Return(walletOwnerMapping, nil)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{SubjectID: verifierSubject, Params: PresentationDefinitionParams{Scope: "example-scope", WalletOwnerType: &userWalletType}})

		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "invalid_request - no presentation definition found for 'user' wallet", err.Error())
	})

	t.Run("error - unknown scope", func(t *testing.T) {
		test := newTestClient(t)
		test.policy.EXPECT().PresentationDefinitions(gomock.Any(), "unknown").Return(nil, policy.ErrNotFound)

		response, err := test.client.PresentationDefinition(ctx, PresentationDefinitionRequestObject{SubjectID: verifierSubject, Params: PresentationDefinitionParams{Scope: "unknown"}})

		require.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, "invalid_scope - not found", err.Error())
	})
}

func TestWrapper_HandleAuthorizeRequest(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		ctx := newCustomTestClient(t, verifierURL, false)

		response, err := ctx.client.HandleAuthorizeRequest(nil, HandleAuthorizeRequestRequestObject{SubjectID: verifierSubject})

		requireOAuthError(t, err, oauth.InvalidRequest, "authorization endpoint is disabled")
		assert.Nil(t, response)
	})
	t.Run("ok - response_type=code", func(t *testing.T) {
		ctx := newTestClient(t)

		// HandleAuthorizeRequest
		requestParams := oauthParameters{
			jwt.AudienceKey:                []string{verifierURL.String()},
			jwt.IssuerKey:                  holderDID.String(),
			oauth.ClientIDParam:            holderClientID,
			oauth.NonceParam:               "nonce",
			oauth.RedirectURIParam:         "https://example.com",
			oauth.ResponseTypeParam:        oauth.CodeResponseType,
			oauth.ScopeParam:               "test",
			oauth.StateParam:               "state",
			oauth.CodeChallengeParam:       "code_challenge",
			oauth.CodeChallengeMethodParam: "S256",
		}
		ctx.jar.EXPECT().Parse(gomock.Any(), gomock.Any(), url.Values{"key": []string{"test_value"}}).Return(requestParams, nil)

		// handleAuthorizeRequestFromHolder
		expectedURL := "https://example.com/authorize?client_id=https://example.com/oauth2/verifier&request_uri=https://example.com/oauth2/verifier/request.jwt/&request_uri_method=get"
		serverMetadata := oauth.AuthorizationServerMetadata{
			Issuer:                     holderClientID,
			AuthorizationEndpoint:      "https://example.com/authorize",
			ClientIdSchemesSupported:   []string{entityClientIDScheme},
			VPFormats:                  oauth.DefaultOpenIDSupportedFormats(),
			RequireSignedRequestObject: true,
		}
		configuration := oauth.OpenIDConfiguration{
			Metadata: oauth.EntityStatementMetadata{
				OpenIDProvider: serverMetadata,
			},
		}
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), "test").Return(pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}, nil)
		ctx.iamClient.EXPECT().OpenIDConfiguration(gomock.Any(), holderURL.String()).Return(&configuration, nil)
		ctx.jar.EXPECT().Create(verifierDID, verifierURL.String(), holderClientID, gomock.Any()).DoAndReturn(func(client did.DID, clientID string, audience string, modifier requestObjectModifier) jarRequest {
			req := createJarRequest(client, clientID, audience, modifier)
			params := req.Claims
			// check the parameters
			assert.NotEmpty(t, params[oauth.NonceParam])
			assert.Equal(t, entityClientIDScheme, params[oauth.ClientIDSchemeParam])
			assert.Equal(t, oauth.VPTokenResponseType, params[oauth.ResponseTypeParam])
			assert.Equal(t, "https://example.com/oauth2/verifier/response", params[oauth.ResponseURIParam])
			assert.Equal(t, "https://example.com/oauth2/verifier/oauth-client", params[oauth.ClientMetadataURIParam])
			assert.Equal(t, responseModeDirectPost, params[oauth.ResponseModeParam])
			assert.NotEmpty(t, params[oauth.StateParam])
			return req
		})

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{"key": "test_value"}),
			HandleAuthorizeRequestRequestObject{SubjectID: verifierSubject})

		require.NoError(t, err)
		require.IsType(t, HandleAuthorizeRequest302Response{}, res)
		testAuthzReqRedirectURI(t, expectedURL, res.(HandleAuthorizeRequest302Response).Headers.Location)
	})
	t.Run("ok - response_type=vp_token", func(t *testing.T) {
		ctx := newTestClient(t)
		vmId := did.DIDURL{
			DID:             verifierDID,
			Fragment:        "key",
			DecodedFragment: "key",
		}
		key, _ := spi.GenerateKeyPair()
		didDocument := did.Document{ID: verifierDID}
		vm, _ := did.NewVerificationMethod(vmId, ssi.JsonWebKey2020, did.DID{}, key.Public())
		didDocument.AddAssertionMethod(vm)

		// HandleAuthorizeRequest
		requestParams := oauthParameters{
			oauth.ClientIDParam:           verifierDID.String(),
			oauth.ClientIDSchemeParam:     entityClientIDScheme,
			oauth.ClientMetadataURIParam:  "https://example.com/.well-known/authorization-server/oauth2/verifier",
			oauth.NonceParam:              "nonce",
			oauth.PresentationDefUriParam: "https://example.com/oauth2/verifier/presentation_definition?scope=test",
			oauth.ResponseURIParam:        "https://example.com/oauth2/verifier/response",
			oauth.ResponseModeParam:       responseModeDirectPost,
			oauth.ResponseTypeParam:       oauth.VPTokenResponseType,
			oauth.ScopeParam:              "test",
			oauth.StateParam:              "state",
		}
		ctx.jar.EXPECT().Parse(gomock.Any(), gomock.Any(), gomock.Any()).Return(requestParams, nil)

		// handleAuthorizeRequestFromVerifier
		_ = ctx.client.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...).Put("state", OAuthSession{
			// this is the state from the holder that was stored at the creation of the first authorization request to the verifier
			ClientID:    holderClientID,
			Scope:       "test",
			OwnSubject:  &holderSubjectID,
			ClientState: "state",
			RedirectURI: "https://example.com/iam/holder/cb",
		})
		callCtx, _ := user.CreateTestSession(requestContext(nil), holderSubjectID)
		clientMetadata := oauth.OAuthClientMetadata{VPFormats: oauth.DefaultOpenIDSupportedFormats()}
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/oauth2/verifier").Return(&clientMetadata, nil)
		pdEndpoint := "https://example.com/oauth2/verifier/presentation_definition?scope=test"
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(&pe.PresentationDefinition{}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{holderDID}, nil, pe.PresentationDefinition{}, clientMetadata.VPFormats, gomock.Any()).Return(&vc.VerifiablePresentation{}, &pe.PresentationSubmission{}, nil)
		ctx.iamClient.EXPECT().PostAuthorizationResponse(gomock.Any(), vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "https://example.com/oauth2/verifier/response", "state").Return("https://example.com/iam/holder/redirect", nil)

		res, err := ctx.client.HandleAuthorizeRequest(callCtx, HandleAuthorizeRequestRequestObject{
			SubjectID: holderSubjectID,
		})

		require.NoError(t, err)
		assert.IsType(t, HandleAuthorizeRequest302Response{}, res)
		location := res.(HandleAuthorizeRequest302Response).Headers.Location
		assert.Equal(t, location, "https://example.com/iam/holder/redirect")
	})
	t.Run("unsupported response_type", func(t *testing.T) {
		ctx := newTestClient(t)
		requestParams := oauthParameters{
			oauth.ClientIDParam:     holderClientID,
			oauth.ResponseTypeParam: "unsupported",
		}
		ctx.jar.EXPECT().Parse(gomock.Any(), gomock.Any(), gomock.Any()).Return(requestParams, nil)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{}),
			HandleAuthorizeRequestRequestObject{SubjectID: verifierSubject})

		requireOAuthError(t, err, oauth.UnsupportedResponseType, "")
		assert.Nil(t, res)
	})
}

func TestWrapper_HandleTokenRequest(t *testing.T) {
	t.Run("unsupported grant type", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.HandleTokenRequest(nil, HandleTokenRequestRequestObject{
			SubjectID: verifierSubject,
			Body: &HandleTokenRequestFormdataRequestBody{
				GrantType: "unsupported",
			},
		})

		requireOAuthError(t, err, oauth.UnsupportedGrantType, "grant_type 'unsupported' is not supported")
		assert.Nil(t, res)
	})
	t.Run("missing clientID", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.HandleTokenRequest(nil, HandleTokenRequestRequestObject{
			SubjectID: verifierSubject,
			Body: &HandleTokenRequestFormdataRequestBody{
				GrantType: oauth.VpTokenGrantType,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing required parameters")
		assert.Nil(t, res)
	})
}

func TestWrapper_Callback(t *testing.T) {
	code := "code"
	errorCode := "error"
	errorDescription := "error description"
	state := "state"
	token := "token"
	redirectURI, parseErr := url.Parse("https://example.com/iam/holder/cb")
	require.NoError(t, parseErr)

	session := OAuthSession{
		ClientFlow:    "access_token_request",
		SessionID:     "token",
		OwnSubject:    &holderSubjectID,
		RedirectURI:   redirectURI.String(),
		OtherDID:      &verifierDID,
		TokenEndpoint: "https://example.com/token",
	}
	t.Run("disabled", func(t *testing.T) {
		ctx := newCustomTestClient(t, verifierURL, false)

		response, err := ctx.client.Callback(nil, CallbackRequestObject{SubjectID: holderSubjectID})

		requireOAuthError(t, err, oauth.InvalidRequest, "callback endpoint is disabled")
		assert.Nil(t, response)
	})
	t.Run("ok - error flow", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, "state", session)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				State:            &state,
				Error:            &errorCode,
				ErrorDescription: &errorDescription,
			},
		})

		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.OAuth2Error{
			Code:        oauth.ErrorCode(errorCode),
			Description: errorDescription,
			RedirectURI: redirectURI,
		}, err)
		assert.Nil(t, res)
	})
	t.Run("ok - success flow", func(t *testing.T) {
		ctx := newTestClient(t)
		withDPoP := session
		withDPoP.UseDPoP = true
		putState(ctx, "state", withDPoP)
		putToken(ctx, token)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, session.TokenEndpoint, "https://example.com/oauth2/holder/callback", holderSubjectID, holderClientID, codeVerifier, true).Return(&oauth.TokenResponse{AccessToken: "access"}, nil)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
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
			ClientFlow:    "access_token_request",
			OwnSubject:    &holderSubjectID,
			PKCEParams:    generatePKCEParams(),
			RedirectURI:   "https://example.com/iam/holder/cb",
			SessionID:     "token",
			UseDPoP:       false,
			OtherDID:      &verifierDID,
			TokenEndpoint: session.TokenEndpoint,
		})
		putToken(ctx, token)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, session.TokenEndpoint, "https://example.com/oauth2/holder/callback", holderSubjectID, holderClientID, codeVerifier, false).Return(&oauth.TokenResponse{AccessToken: "access"}, nil)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, res)
	})
	t.Run("err - did mismatch", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, "state", session)

		res, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: verifierSubject,
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		assert.Nil(t, res)
		requireOAuthError(t, err, oauth.InvalidRequest, "session subject does not match request")

	})
	t.Run("err - missing state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				Code: &code,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing state parameter")
	})
	t.Run("err - error flow but missing state", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				Error:            &errorCode,
				ErrorDescription: &errorDescription,
			},
		})

		requireOAuthError(t, err, oauth.ErrorCode(errorCode), errorDescription)
		assert.EqualError(t, err, "error - missing state parameter - error description")
	})
	t.Run("err - expired state/session", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: verifierSubject,
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid or expired state")
	})
	t.Run("err - missing code", func(t *testing.T) {
		ctx := newTestClient(t)
		putState(ctx, "state", session)

		_, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "missing code parameter")
	})
	t.Run("err - unknown flow", func(t *testing.T) {
		ctx := newTestClient(t)
		_ = ctx.client.oauthClientStateStore().Put(state, OAuthSession{
			ClientFlow: "",
			OwnSubject: &holderSubjectID,
		})

		_, err := ctx.client.Callback(nil, CallbackRequestObject{
			SubjectID: holderSubjectID,
			Params: CallbackParams{
				Code:  &code,
				State: &state,
			},
		})

		requireOAuthError(t, err, oauth.ServerError, "unknown client flow for callback: ''")
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
	okToken := AccessToken{
		Expiration: time.Now().Add(time.Hour),
		DPoP:       dpopToken,
		PresentationSubmissions: map[string]pe.PresentationSubmission{
			"test": {},
		},
		PresentationDefinitions: RequiredPresentationDefinitions{
			pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"},
		},
		VPToken: []VerifiablePresentation{
			{},
		},
	}
	t.Run("ok", func(t *testing.T) {
		token := okToken
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessToken(context.Background(), IntrospectAccessTokenRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.NoError(t, err)
		tokenResponse, ok := res.(IntrospectAccessToken200JSONResponse)
		require.True(t, ok)
		assert.True(t, tokenResponse.Active)
		assert.Nil(t, tokenResponse.PresentationSubmissions)
		assert.Nil(t, tokenResponse.PresentationDefinitions)
		assert.Nil(t, tokenResponse.Vps)
	})
	t.Run("extended", func(t *testing.T) {
		token := okToken
		require.NoError(t, ctx.client.accessTokenServerStore().Put("token", token))

		res, err := ctx.client.IntrospectAccessTokenExtended(context.Background(), IntrospectAccessTokenExtendedRequestObject{Body: &TokenIntrospectionRequest{Token: "token"}})

		require.NoError(t, err)
		tokenResponse, ok := res.(IntrospectAccessTokenExtended200JSONResponse)
		require.True(t, ok)
		assert.True(t, tokenResponse.Active)
		assert.NotNil(t, tokenResponse.PresentationSubmissions)
		assert.NotNil(t, tokenResponse.PresentationDefinitions)
		assert.NotNil(t, tokenResponse.Vps)
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
		expectedResponse, err := json.Marshal(IntrospectAccessTokenExtended200JSONResponse{
			Active:                  true,
			ClientId:                to.Ptr("client"),
			Cnf:                     &Cnf{Jkt: thumbprint},
			Exp:                     to.Ptr(int(tNow.Add(time.Minute).Unix())),
			Iat:                     to.Ptr(int(tNow.Unix())),
			Iss:                     to.Ptr("resource-owner"),
			Scope:                   to.Ptr("test"),
			Sub:                     to.Ptr("resource-owner"),
			Vps:                     &[]VerifiablePresentation{presentation},
			PresentationSubmissions: to.Ptr(presentationSubmissions),
			PresentationDefinitions: to.Ptr(presentationDefinitions),
			AdditionalProperties:    map[string]interface{}{"key": "value"},
		})
		require.NoError(t, err)

		res, err := ctx.client.IntrospectAccessTokenExtended(context.Background(), IntrospectAccessTokenExtendedRequestObject{Body: &TokenIntrospectionRequest{Token: token.Token}})

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
		(&Wrapper{
			storageEngine: storage.NewTestStorageEngine(t),
		}).Routes(router)

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

func TestWrapper_RequestServiceAccessToken(t *testing.T) {
	body := &RequestServiceAccessTokenJSONRequestBody{
		AuthorizationServer: verifierURL.String(),
		Scope:               "first second",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, holderClientID, holderSubjectID, verifierURL.String(), "first second", true, nil).Return(&oauth.TokenResponse{}, nil)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

		require.NoError(t, err)
	})
	t.Run("ok - no DPoP", func(t *testing.T) {
		ctx := newTestClient(t)
		tokenTypeBearer := ServiceAccessTokenRequestTokenType("bearer")
		body := &RequestServiceAccessTokenJSONRequestBody{
			AuthorizationServer: verifierURL.String(),
			Scope:               "first second",
			TokenType:           &tokenTypeBearer,
		}
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, holderClientID, holderSubjectID, verifierURL.String(), "first second", false, nil).Return(&oauth.TokenResponse{}, nil)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

		require.NoError(t, err)
	})
	t.Run("error - no matching credentials", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, holderClientID, holderSubjectID, verifierURL.String(), "first second", true, nil).Return(nil, holder.ErrNoCredentials)

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

		require.Error(t, err)
		assert.Equal(t, err, holder.ErrNoCredentials)
		assert.Equal(t, http.StatusPreconditionFailed, statusCodeFrom(err))
	})
}

func TestWrapper_RequestUserAccessToken(t *testing.T) {
	tokenType := UserAccessTokenRequestTokenType("dpop")
	userDetails := UserDetails{
		Id:   "test",
		Name: "Titus Tester",
		Role: "Test Manager",
	}
	redirectURI := "https://test.test/oauth2/" + holderDID.String() + "/cb"
	body := &RequestUserAccessTokenJSONRequestBody{
		AuthorizationServer: "https://example.com",
		Scope:               "first second",
		PreauthorizedUser:   &userDetails,
		RedirectUri:         redirectURI,
		TokenType:           &tokenType,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		response, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

		// assert token
		require.NoError(t, err)
		redirectResponse, ok := response.(RequestUserAccessToken200JSONResponse)
		assert.True(t, ok)
		assert.Contains(t, redirectResponse.RedirectUri, "https://example.com/oauth2/"+holderSubjectID+"/user?token=")

		// assert session
		var target RedirectSession
		redirectURI, _ := url.Parse(redirectResponse.RedirectUri)
		err = ctx.client.userRedirectStore().Get(redirectURI.Query().Get("token"), &target)
		require.NoError(t, err)
		assert.Equal(t, holderSubjectID, target.SubjectID)
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
		ctx.documentOwner.EXPECT().IsOwner(nil, holderDID).AnyTimes().Return(true, nil)
		t.Run("error - missing preauthorized_user", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{
				AuthorizationServer: "https://example.com",
				Scope:               "first second",
				RedirectUri:         redirectURI,
			}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

			require.EqualError(t, err, "missing preauthorized_user")
		})
		t.Run("error - missing preauthorized_user.id", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{
				AuthorizationServer: "https://example.com",
				Scope:               "first second",
				PreauthorizedUser:   &UserDetails{Name: "Titus Tester"},
				RedirectUri:         redirectURI,
			}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

			require.EqualError(t, err, "missing preauthorized_user.id")
		})
		t.Run("error - missing preauthorized_user.name", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{
				AuthorizationServer: "https://example.com",
				Scope:               "first second",
				PreauthorizedUser:   &UserDetails{Id: "test"},
				RedirectUri:         redirectURI,
			}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

			require.EqualError(t, err, "missing preauthorized_user.name")
		})
		t.Run("error - missing preauthorized_user.role", func(t *testing.T) {
			body := &RequestUserAccessTokenJSONRequestBody{
				AuthorizationServer: "https://example.com",
				Scope:               "first second",
				PreauthorizedUser:   &UserDetails{Id: "test", Name: "Titus Tester"},
				RedirectUri:         redirectURI,
			}

			_, err := ctx.client.RequestUserAccessToken(nil, RequestUserAccessTokenRequestObject{SubjectID: holderSubjectID, Body: body})

			require.EqualError(t, err, "missing preauthorized_user.role")
		})
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

		res, err := ctx.client.StatusList(nil, StatusListRequestObject{Did: verifierDID.String()})

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
		ro := jar{}.Create(holderDID, holderClientID, verifierClientID, func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return(expectedToken, nil)

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{SubjectID: holderSubjectID, Id: requestID})

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
		ro := jar{}.Create(holderDID, holderClientID, verifierClientID, func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{SubjectID: unknownSubjectID, Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - client_id does not match request")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - wrong request_uri_method used", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(holderDID, holderClientID, verifierURL.String(), func(claims map[string]string) {})
		ro.RequestURIMethod = "post"
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{SubjectID: holderSubjectID, Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "invalid_request - wrong 'request_uri_method' authorization server or wallet probably does not support 'request_uri_method' - used request_uri_method 'get' on a 'post' request_uri")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
	t.Run("error - signing failed", func(t *testing.T) {
		ctx := newTestClient(t)
		ro := jar{}.Create(holderDID, holderClientID, verifierURL.String(), func(claims map[string]string) {})
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return("", errors.New("fail"))

		response, err := ctx.client.RequestJWTByGet(cont, RequestJWTByGetRequestObject{SubjectID: holderSubjectID, Id: requestID})

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
		ro := jar{}.Create(holderDID, holderClientID, "", func(claims map[string]string) {})
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
		ro := newReqObj("", "")
		require.NoError(t, ctx.client.authzRequestObjectStore().Put(requestID, ro))
		ctx.jar.EXPECT().Sign(cont, ro.Claims).Return(expectedToken, nil)

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{SubjectID: holderSubjectID, Id: requestID})

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

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{SubjectID: holderSubjectID, Id: requestID, Body: &body})

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

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{SubjectID: unknownSubjectID, Id: requestID})

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

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{SubjectID: holderSubjectID, Id: requestID})

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

		response, err := ctx.client.RequestJWTByPost(cont, RequestJWTByPostRequestObject{SubjectID: holderSubjectID, Id: requestID})

		assert.Nil(t, response)
		assert.EqualError(t, err, "server_error - failed to sign authorization Request Object: fail - unable to create Request Object")
		// requestObject is burned
		assert.ErrorIs(t, ctx.client.authzRequestObjectStore().Get(requestID, new(jarRequest)), storage.ErrNotFound)
	})
}

func TestWrapper_CreateAuthorizationRequest(t *testing.T) {
	modifier := func(values map[string]string) {
		values["custom"] = "value"
	}
	serverMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:      "https://server.test/authorize",
		Issuer:                     issuerURL.String(),
		ClientIdSchemesSupported:   clientIdSchemesSupported,
		RequireSignedRequestObject: true,
	}
	t.Run("ok - RequireSignedRequestObject=true", func(t *testing.T) {
		expectedRedirect := "https://server.test/authorize?client_id=https://example.com/oauth2/holder&request_uri=https://example.com/oauth2/&request_uri_method=custom"
		var expectedJarReq jarRequest
		ctx := newTestClient(t)
		ctx.jar.EXPECT().Create(holderDID, holderClientID, issuerURL.String(), gomock.Any()).DoAndReturn(func(client did.DID, clientID string, authServerURL string, modifier requestObjectModifier) jarRequest {
			expectedJarReq = createJarRequest(client, clientID, authServerURL, modifier)
			expectedJarReq.RequestURIMethod = "custom"
			assert.Equal(t, "value", expectedJarReq.Claims.get("custom"))
			return expectedJarReq
		})

		redirectURL, err := ctx.client.createAuthorizationRequest(context.Background(), holderSubjectID, serverMetadata, modifier)

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
		ctx.jar.EXPECT().Create(holderDID, holderClientID, "", gomock.Any()).DoAndReturn(func(client did.DID, clientID string, authServerURL string, modifier requestObjectModifier) jarRequest {
			expectedJarReq = createJarRequest(client, clientID, authServerURL, modifier)
			assert.Equal(t, "value", expectedJarReq.Claims.get("custom"))
			return expectedJarReq
		})
		customMetadata := serverMetadata
		customMetadata.Issuer = ""
		customMetadata.RequireSignedRequestObject = false

		redirectURL, err := ctx.client.createAuthorizationRequest(context.Background(), holderSubjectID, customMetadata, modifier)

		assert.NoError(t, err)
		assert.Equal(t, "value", redirectURL.Query().Get("custom"))
		assert.Equal(t, holderClientID, redirectURL.Query().Get(oauth.ClientIDParam))
		assert.Equal(t, "post", redirectURL.Query().Get(oauth.RequestURIMethodParam))
		assert.NotEmpty(t, redirectURL.Query().Get(oauth.RequestURIParam))
	})
	t.Run("error - missing authorization endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		customMetadata := serverMetadata
		customMetadata.AuthorizationEndpoint = ""

		_, err := ctx.client.createAuthorizationRequest(context.Background(), holderSubjectID, customMetadata, modifier)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "no authorization endpoint found in metadata for")
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

func TestWrapper_subjectExists(t *testing.T) {
	t.Run("unknown subject", func(t *testing.T) {
		ctx := newTestClient(t)

		err := ctx.client.subjectExists(context.Background(), unknownSubjectID)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
	t.Run("subject exists", func(t *testing.T) {
		ctx := newTestClient(t)

		err := ctx.client.subjectExists(context.Background(), holderSubjectID)

		assert.NoError(t, err)
	})
}

func TestWrapper_subjectOwns(t *testing.T) {
	t.Run("unknown subject", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.subjectOwns(context.Background(), unknownSubjectID, holderDID)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
	t.Run("DID owned by subject", func(t *testing.T) {
		ctx := newTestClient(t)

		owned, err := ctx.client.subjectOwns(context.Background(), holderSubjectID, holderDID)

		assert.NoError(t, err)
		assert.True(t, owned)
	})
	t.Run("DID not owned by subject", func(t *testing.T) {
		ctx := newTestClient(t)

		owned, err := ctx.client.subjectOwns(context.Background(), holderSubjectID, did.MustParseDID("did:web:example.com:iam:456"))

		assert.NoError(t, err)
		assert.False(t, owned)
	})
}

func createIssuerCredential(issuerDID did.DID, holderDID did.DID) *vc.VerifiableCredential {
	privateKey, _ := spi.GenerateKeyPair()
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
		sign, err := jwt.Sign(request, jwt.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(hdrs)))
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
	authnServices  *auth.MockAuthenticationServices
	ctrl           *gomock.Controller
	client         *Wrapper
	documentOwner  *didsubject.MockDocumentOwner
	iamClient      *iam.MockClient
	jwtSigner      *cryptoNuts.MockJWTSigner
	keyResolver    *resolver.MockKeyResolver
	policy         *policy.MockPDPBackend
	resolver       *resolver.MockDIDResolver
	relyingParty   *oauthServices.MockRelyingParty
	vcr            *vcr.MockVCR
	vdr            *vdr.MockVDR
	vcIssuer       *issuer.MockIssuer
	vcVerifier     *verifier.MockVerifier
	wallet         *holder.MockWallet
	subjectManager *didsubject.MockSubjectManager
	jar            *MockJAR
}

func newTestClient(t testing.TB) *testCtx {
	publicURL, _ := url.Parse("https://example.com")
	return newCustomTestClient(t, publicURL, true)
}

func newCustomTestClient(t testing.TB, publicURL *url.URL, authEndpointEnabled bool) *testCtx {
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
	mockDocumentOwner := didsubject.NewMockDocumentOwner(ctrl)
	subjectManager := didsubject.NewMockSubjectManager(ctrl)
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
	authnServices.EXPECT().AuthorizationEndpointEnabled().Return(authEndpointEnabled).AnyTimes()
	mockVDR.EXPECT().Resolver().Return(mockResolver).AnyTimes()
	mockVDR.EXPECT().DocumentOwner().Return(mockDocumentOwner).AnyTimes()
	mockVDR.EXPECT().SupportedMethods().Return([]string{"web"}).AnyTimes()

	subjectManager.EXPECT().List(gomock.Any(), holderSubjectID).Return([]did.DID{holderDID}, nil).AnyTimes()
	subjectManager.EXPECT().List(gomock.Any(), unknownSubjectID).Return(nil, didsubject.ErrSubjectNotFound).AnyTimes()
	subjectManager.EXPECT().List(gomock.Any(), verifierSubject).Return([]did.DID{verifierDID}, nil).AnyTimes()
	subjectManager.EXPECT().List(gomock.Any(), issuerSubjectID).Return([]did.DID{issuerDID}, nil).AnyTimes()
	subjectManager.EXPECT().Exists(gomock.Any(), holderSubjectID).Return(true, nil).AnyTimes()
	subjectManager.EXPECT().Exists(gomock.Any(), verifierSubject).Return(true, nil).AnyTimes()
	subjectManager.EXPECT().Exists(gomock.Any(), unknownSubjectID).Return(false, nil).AnyTimes()

	client := &Wrapper{
		auth:           authnServices,
		vdr:            mockVDR,
		subjectManager: subjectManager,
		vcr:            mockVCR,
		storageEngine:  storageEngine,
		policyBackend:  policyInstance,
		keyResolver:    keyResolver,
		jwtSigner:      jwtSigner,
		jar:            mockJAR,
	}
	return &testCtx{
		ctrl:           ctrl,
		authnServices:  authnServices,
		policy:         policyInstance,
		relyingParty:   relyingPary,
		vcIssuer:       vcIssuer,
		vcVerifier:     vcVerifier,
		resolver:       mockResolver,
		vdr:            mockVDR,
		documentOwner:  mockDocumentOwner,
		subjectManager: subjectManager,
		iamClient:      iamClient,
		vcr:            mockVCR,
		wallet:         mockWallet,
		keyResolver:    keyResolver,
		jwtSigner:      jwtSigner,
		jar:            mockJAR,
		client:         client,
	}
}
