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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr"
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
	clientMetadata := oauth.OAuthClientMetadata{
		VPFormats: oauth.DefaultOpenIDSupportedFormats(),
	}
	serverMetadata := oauth.AuthorizationServerMetadata{
		ClientIdSchemesSupported: []string{didScheme},
		VPFormats:                oauth.DefaultOpenIDSupportedFormats(),
	}
	pdEndpoint := "https://example.com/oauth2/did:web:example.com:iam:verifier/presentation_definition?scope=test"
	// setup did document and keys
	vmId := did.DIDURL{
		DID:             holderDID,
		Fragment:        "key",
		DecodedFragment: "key",
	}
	kid := vmId.String()
	key := crypto.NewTestKey(kid)
	didDocument := did.Document{ID: holderDID}
	vm, _ := did.NewVerificationMethod(vmId, ssi.JsonWebKey2020, did.DID{}, key.Public())
	didDocument.AddAssertionMethod(vm)

	t.Run("ok - signed request - code response type", func(t *testing.T) {
		ctx := newTestClient(t)

		// create signed request
		request := jwt.New()
		_ = request.Set(jwt.AudienceKey, []string{verifierDID.String()})
		_ = request.Set(jwt.IssuerKey, holderDID.String())
		_ = request.Set(oauth.ClientIDParam, holderDID.String())
		_ = request.Set(oauth.NonceParam, "nonce")
		_ = request.Set(oauth.RedirectURIParam, "https://example.com")
		_ = request.Set(oauth.ResponseTypeParam, responseTypeCode)
		_ = request.Set(oauth.ScopeParam, "test")
		_ = request.Set(oauth.StateParam, "state")
		_ = request.Set(oauth.CodeChallengeParam, "code_challenge")
		_ = request.Set(oauth.CodeChallengeMethodParam, "S256")
		headers := jws.NewHeaders()
		headers.Set(jws.KeyIDKey, kid)
		bytes, err := jwt.Sign(request, jwt.WithKey(jwa.ES256, key.Private(), jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)

		expectedURL := test.MustParseURL("https://example.com/oauth2/did:web:example.com:iam:holder/authorize")
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
		ctx.vdr.EXPECT().Resolve(holderDID, gomock.Any()).Return(&didDocument, &resolver.DocumentMetadata{}, nil)
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), verifierDID, "test").Return(pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&serverMetadata, nil)
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), verifierDID, holderDID, gomock.Any()).DoAndReturn(func(ctx context.Context, verifierDID, holderDID did.DID, modifier iam.RequestModifier) (*url.URL, error) {
			// check the parameters
			params := map[string]interface{}{}
			modifier(params)
			assert.NotEmpty(t, params[oauth.NonceParam])
			assert.Equal(t, didScheme, params[clientIDSchemeParam])
			assert.Equal(t, responseTypeVPToken, params[oauth.ResponseTypeParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/response", params[responseURIParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/oauth-client", params[clientMetadataURIParam])
			assert.Equal(t, responseModeDirectPost, params[responseModeParam])
			assert.NotEmpty(t, params[oauth.StateParam])
			return expectedURL, nil
		})

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			oauth.ClientIDParam: holderDID.String(),
			oauth.RequestParam:  string(bytes),
		}), HandleAuthorizeRequestRequestObject{
			Did: verifierDID.String(),
		})

		require.NoError(t, err)
		assert.IsType(t, HandleAuthorizeRequest302Response{}, res)
		location := res.(HandleAuthorizeRequest302Response).Headers.Location
		assert.Equal(t, location, expectedURL.String())
	})
	t.Run("error - invalid request parameter", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			oauth.ClientIDParam: "invalid",
			oauth.RequestParam:  "invalid",
		}), HandleAuthorizeRequestRequestObject{
			Did: verifierDID.String(),
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "unable to validate request signature")
		assert.Nil(t, res)
	})
	t.Run("error - client_id does not match", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
		ctx.vdr.EXPECT().Resolve(holderDID, gomock.Any()).Return(&didDocument, &resolver.DocumentMetadata{}, nil)
		// create signed request
		request := jwt.New()
		_ = request.Set(jwt.IssuerKey, holderDID.String())
		_ = request.Set(oauth.ClientIDParam, holderDID.String())
		headers := jws.NewHeaders()
		headers.Set(jws.KeyIDKey, kid)
		bytes, err := jwt.Sign(request, jwt.WithKey(jwa.ES256, key.Private(), jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			oauth.ClientIDParam: "invalid",
			oauth.RequestParam:  string(bytes),
		}), HandleAuthorizeRequestRequestObject{
			Did: verifierDID.String(),
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid client_id claim in signed authorization request")
		assert.Nil(t, res)
	})
	t.Run("error - client_id does not match signer", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
		ctx.vdr.EXPECT().Resolve(holderDID, gomock.Any()).Return(&didDocument, &resolver.DocumentMetadata{}, nil)
		// create signed request
		request := jwt.New()
		_ = request.Set(jwt.IssuerKey, verifierDID.String())
		_ = request.Set(oauth.ClientIDParam, verifierDID.String())
		headers := jws.NewHeaders()
		headers.Set(jws.KeyIDKey, kid)
		bytes, err := jwt.Sign(request, jwt.WithKey(jwa.ES256, key.Private(), jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			oauth.ClientIDParam: verifierDID.String(),
			oauth.RequestParam:  string(bytes),
		}), HandleAuthorizeRequestRequestObject{
			Did: verifierDID.String(),
		})

		requireOAuthError(t, err, oauth.InvalidRequest, "client_id does not match signer of authorization request")
		assert.Nil(t, res)
	})
	t.Run("ok - code response type - from holder", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL := test.MustParseURL("https://example.com/iam/holder/authorize")
		ctx.policy.EXPECT().PresentationDefinitions(gomock.Any(), verifierDID, "test").Return(pe.WalletOwnerMapping{pe.WalletOwnerOrganization: pe.PresentationDefinition{Id: "test"}}, nil)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), verifierDID).Return(true, nil)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&serverMetadata, nil)
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), verifierDID, holderDID, gomock.Any()).DoAndReturn(func(ctx context.Context, verifierDID, holderDID did.DID, modifier iam.RequestModifier) (*url.URL, error) {
			// check the parameters
			params := map[string]interface{}{}
			modifier(params)
			assert.NotEmpty(t, params[oauth.NonceParam])
			assert.Equal(t, didScheme, params[clientIDSchemeParam])
			assert.Equal(t, responseTypeVPToken, params[oauth.ResponseTypeParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/response", params[responseURIParam])
			assert.Equal(t, "https://example.com/oauth2/did:web:example.com:iam:verifier/oauth-client", params[clientMetadataURIParam])
			assert.Equal(t, responseModeDirectPost, params[responseModeParam])
			assert.NotEmpty(t, params[oauth.StateParam])
			return expectedURL, nil
		})

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			jwt.AudienceKey:                verifierDID.String(),
			jwt.IssuerKey:                  holderDID.String(),
			oauth.ClientIDParam:            holderDID.String(),
			oauth.NonceParam:               "nonce",
			oauth.RedirectURIParam:         "https://example.com",
			oauth.ResponseTypeParam:        responseTypeCode,
			oauth.ScopeParam:               "test",
			oauth.StateParam:               "state",
			oauth.CodeChallengeParam:       "code_challenge",
			oauth.CodeChallengeMethodParam: "S256",
		}), HandleAuthorizeRequestRequestObject{
			Did: verifierDID.String(),
		})

		require.NoError(t, err)
		assert.IsType(t, HandleAuthorizeRequest302Response{}, res)
		location := res.(HandleAuthorizeRequest302Response).Headers.Location
		assert.Equal(t, location, expectedURL.String())

	})
	t.Run("ok - vp_token response type - from verifier", func(t *testing.T) {
		ctx := newTestClient(t)
		_ = ctx.client.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...).Put("state", OAuthSession{
			// this is the state from the holder that was stored at the creation of the first authorization request to the verifier
			ClientID:     holderDID.String(),
			Scope:        "test",
			OwnDID:       &holderDID,
			ClientState:  "state",
			RedirectURI:  "https://example.com/iam/holder/cb",
			ResponseType: "code",
		})
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().ClientMetadata(gomock.Any(), "https://example.com/.well-known/authorization-server/iam/verifier").Return(&clientMetadata, nil)
		ctx.iamClient.EXPECT().PresentationDefinition(gomock.Any(), pdEndpoint).Return(&pe.PresentationDefinition{}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), holderDID, pe.PresentationDefinition{}, clientMetadata.VPFormats, gomock.Any()).Return(&vc.VerifiablePresentation{}, &pe.PresentationSubmission{}, nil)
		ctx.iamClient.EXPECT().PostAuthorizationResponse(gomock.Any(), vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "https://example.com/oauth2/did:web:example.com:iam:verifier/response", "state").Return("https://example.com/iam/holder/redirect", nil)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			oauth.ClientIDParam:     verifierDID.String(),
			clientIDSchemeParam:     didScheme,
			clientMetadataURIParam:  "https://example.com/.well-known/authorization-server/iam/verifier",
			oauth.NonceParam:        "nonce",
			presentationDefUriParam: "https://example.com/oauth2/did:web:example.com:iam:verifier/presentation_definition?scope=test",
			responseURIParam:        "https://example.com/oauth2/did:web:example.com:iam:verifier/response",
			responseModeParam:       responseModeDirectPost,
			oauth.ResponseTypeParam: responseTypeVPToken,
			oauth.ScopeParam:        "test",
			oauth.StateParam:        "state",
		}), HandleAuthorizeRequestRequestObject{
			Did: "did:web:example.com:iam:holder",
		})

		require.NoError(t, err)
		assert.IsType(t, HandleAuthorizeRequest302Response{}, res)
		location := res.(HandleAuthorizeRequest302Response).Headers.Location
		assert.Equal(t, location, "https://example.com/iam/holder/redirect")
	})
	t.Run("unsupported response type", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)

		res, err := ctx.client.HandleAuthorizeRequest(requestContext(map[string]interface{}{
			"redirect_uri":  "https://example.com",
			"response_type": "unsupported",
		}), HandleAuthorizeRequestRequestObject{
			Did: webDID.String(),
		})

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
		SessionID:   "token",
		OwnDID:      &holderDID,
		RedirectURI: "https://example.com/iam/holder/cb",
		VerifierDID: &verifierDID,
	}

	t.Run("ok - error flow", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		putState(ctx, session)

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
		putState(ctx, session)
		putToken(ctx, token)
		codeVerifier := getState(ctx, state).PKCEParams.Verifier
		ctx.vdr.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil).Times(2)
		ctx.iamClient.EXPECT().AccessToken(gomock.Any(), code, verifierDID, "https://example.com/oauth2/did:web:example.com:iam:123/callback", holderDID, codeVerifier).Return(&oauth.TokenResponse{AccessToken: "access"}, nil)

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
		assert.Equal(t, oauth.AccessTokenRequestStatusActive, *tokenResponse.Status)
		assert.Equal(t, "access", tokenResponse.AccessToken)
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
	})
	t.Run("error - unknown sessionID", func(t *testing.T) {
		ctx := newTestClient(t)

		res, err := ctx.client.RetrieveAccessToken(nil, request)

		assert.Equal(t, storage.ErrNotFound, err)
		assert.Nil(t, res)
	})
}

func TestWrapper_IntrospectAccessToken(t *testing.T) {
	// mvp to store access token
	ctx := newTestClient(t)

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
		token := AccessToken{Expiration: time.Now().Add(time.Second)}
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

		require.EqualError(t, err, "IntrospectAccessToken: InputDescriptorConstraintIdMap contains reserved claim name 'iss'")
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
		token := AccessToken{
			Token:                          "token",
			Issuer:                         "resource-owner",
			ClientId:                       "client",
			IssuedAt:                       tNow,
			Expiration:                     tNow.Add(time.Minute),
			Scope:                          "test",
			InputDescriptorConstraintIdMap: map[string]any{"key": "value"},
			VPToken:                        []VerifiablePresentation{presentation},
			PresentationSubmissions:        &pe.PresentationSubmission{},
			PresentationDefinitions:        &pe.PresentationDefinition{},
		}

		require.NoError(t, ctx.client.accessTokenServerStore().Put(token.Token, token))
		expectedResponse, err := json.Marshal(IntrospectAccessToken200JSONResponse{
			Active:                 true,
			ClientId:               ptrTo("client"),
			Exp:                    ptrTo(int(tNow.Add(time.Minute).Unix())),
			Iat:                    ptrTo(int(tNow.Unix())),
			Iss:                    ptrTo("resource-owner"),
			Scope:                  ptrTo("test"),
			Sub:                    ptrTo("resource-owner"),
			Vps:                    &[]VerifiablePresentation{presentation},
			PresentationSubmission: ptrTo(map[string]interface{}{"definition_id": "", "descriptor_map": nil, "id": ""}),
			PresentationDefinition: ptrTo(map[string]interface{}{"id": "", "input_descriptors": nil}),
			AdditionalProperties:   map[string]interface{}{"key": "value"},
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
	ctrl := gomock.NewController(t)
	router := core.NewMockEchoRouter(ctrl)

	router.EXPECT().GET(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	router.EXPECT().POST(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	(&Wrapper{}).Routes(router)
}

func TestWrapper_middleware(t *testing.T) {
	server := echo.New()
	ctrl := gomock.NewController(t)
	authService := auth.NewMockAuthenticationServices(ctrl)

	t.Run("OAuth2 error handling", func(t *testing.T) {
		var handler strictServerCallCapturer
		t.Run("OAuth2 path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/iam/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", handler.handle)

			assert.IsType(t, &oauth.Oauth2ErrorWriter{}, ctx.Get(core.ErrorWriterContextKey))
		})
		t.Run("other path", func(t *testing.T) {
			ctx := server.NewContext(httptest.NewRequest("GET", "/internal/foo", nil), httptest.NewRecorder())
			_, _ = Wrapper{auth: authService}.middleware(ctx, nil, "Test", handler.handle)

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

	t.Run("ok - service flow", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second").Return(&oauth.TokenResponse{}, nil)

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
		ctx.iamClient.EXPECT().RequestRFC021AccessToken(nil, walletDID, verifierDID, "first second").Return(nil, core.Error(http.StatusPreconditionFailed, "no matching credentials"))

		_, err := ctx.client.RequestServiceAccessToken(nil, RequestServiceAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "no matching credentials")
	})
}

func TestWrapper_RequestUserAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")
	userDetails := UserDetails{
		Id:   "test",
		Name: "Titus Tester",
		Role: "Test Manager",
	}
	redirectURI := "https://test.test/oauth2/" + walletDID.String() + "/cb"
	body := &RequestUserAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", PreauthorizedUser: &userDetails, RedirectUri: redirectURI}

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

		// assert flow
		var tokenResponse TokenResponse
		require.NotNil(t, redirectResponse.SessionId)
		err = ctx.client.accessTokenClientStore().Get(redirectResponse.SessionId, &tokenResponse)
		assert.Equal(t, oauth.AccessTokenRequestStatusPending, *tokenResponse.Status)
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

func TestWrapper_RequestOid4vciCredentialIssuance(t *testing.T) {
	holderDID := did.MustParseDID("did:web:holder.test:iam:123")
	issuerDID := did.MustParseDID("did:web:issuer.test:iam:456")
	redirectURI := "https://test.test/iam/123/cb"
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		authServer := "https://auth.server/"
		authServerUrl, _ := url.Parse(authServer)
		metadata := oauth.OpenIDCredentialIssuerMetadata{
			CredentialIssuer:     "issuer",
			CredentialEndpoint:   "endpoint",
			AuthorizationServers: []string{authServer},
			Display:              nil,
		}
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerDID).Return(&metadata, nil)
		openidMetadata := oauth.OpenIDConfigurationMetadata{
			AuthorizationEndpoint: "https://auth.server/authorize",
			TokenEndpoint:         "https://auth.server/token",
		}
		ctx.iamClient.EXPECT().OpenIdConfiguration(nil, authServerUrl.String()).Return(&openidMetadata, nil)
		issuance, err := ctx.client.RequestOid4vciCredentialIssuance(nil, RequestOid4vciCredentialIssuanceRequestObject{
			Did: holderDID.String(),
			Body: &RequestOid4vciCredentialIssuanceJSONRequestBody{
				AuthorizationDetails: []struct {
					CredentialDefinition *map[string]interface{} `json:"credential_definition,omitempty"`
					Format               *string                 `json:"format,omitempty"`
					Type                 *string                 `json:"type,omitempty"`
				}(make([]struct {
					CredentialDefinition *map[string]interface{}
					Format               *string
					Type                 *string
				}, 0)),
				Issuer:      issuerDID.String(),
				RedirectUri: redirectURI,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, issuance)
		actual := issuance.(RequestOid4vciCredentialIssuance200JSONResponse)
		redirectUri, _ := url.Parse(actual.RedirectURI)
		assert.Equal(t, "auth.server", redirectUri.Host)
		assert.Equal(t, "/authorize", redirectUri.Path)
		assert.True(t, redirectUri.Query().Has("state"))
		assert.True(t, redirectUri.Query().Has("code_challenge"))
		assert.Equal(t, "https://holder.test/iam/oid4vci/callback", redirectUri.Query().Get("redirect_uri"))
		assert.Equal(t, holderDID.String(), redirectUri.Query().Get("client_id"))
		assert.Equal(t, "S256", redirectUri.Query().Get("code_challenge_method"))
		assert.Equal(t, "code", redirectUri.Query().Get("response_type"))
	})
	t.Run("no_auth_endpoint_err_1", func(t *testing.T) {
		ctx := newTestClient(t)
		metadata := oauth.OpenIDCredentialIssuerMetadata{
			CredentialIssuer:     "issuer",
			CredentialEndpoint:   "endpoint",
			AuthorizationServers: []string{},
			Display:              nil,
		}
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerDID).Return(&metadata, nil)
		_, err := ctx.client.RequestOid4vciCredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		require.Error(t, err)
	})

	t.Run("no_auth_no_owner", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(false, nil)
		_, err := ctx.client.RequestOid4vciCredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		require.Error(t, err)
		assert.EqualError(t, err, "problem with owner DID: DID document not managed by this node")
	})
	t.Run("no_auth_endpoint_err_2", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerDID).Return(nil, errors.New("ERROR"))
		_, err := ctx.client.RequestOid4vciCredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		require.Error(t, err)
	})
	t.Run("no_auth_endpoint_err_3", func(t *testing.T) {
		ctx := newTestClient(t)
		authServer := "https://auth.server/"
		authServerUrl, _ := url.Parse(authServer)
		metadata := oauth.OpenIDCredentialIssuerMetadata{
			CredentialIssuer:     "issuer",
			CredentialEndpoint:   "endpoint",
			AuthorizationServers: []string{authServer},
			Display:              nil,
		}
		ctx.vdr.EXPECT().IsOwner(nil, holderDID).Return(true, nil)
		ctx.iamClient.EXPECT().OpenIdCredentialIssuerMetadata(nil, issuerDID).Return(&metadata, nil)
		ctx.iamClient.EXPECT().OpenIdConfiguration(nil, authServerUrl.String()).Return(nil, errors.New("ERROR"))
		_, err := ctx.client.RequestOid4vciCredentialIssuance(nil, requestCredentials(holderDID, issuerDID, redirectURI))
		require.Error(t, err)
	})
}

func requestCredentials(holderDID did.DID, issuerDID did.DID, redirectURI string) RequestOid4vciCredentialIssuanceRequestObject {
	return RequestOid4vciCredentialIssuanceRequestObject{
		Did: holderDID.String(),
		Body: &RequestOid4vciCredentialIssuanceJSONRequestBody{
			AuthorizationDetails: []struct {
				CredentialDefinition *map[string]interface{} `json:"credential_definition,omitempty"`
				Format               *string                 `json:"format,omitempty"`
				Type                 *string                 `json:"type,omitempty"`
			}(make([]struct {
				CredentialDefinition *map[string]interface{}
				Format               *string
				Type                 *string
			}, 0)),
			Issuer:      issuerDID.String(),
			RedirectUri: redirectURI,
		},
	}
}

func TestWrapper_CallbackOid4vciCredentialIssuance(t *testing.T) {
	holderDID := did.MustParseDID("did:web:holder.test:iam:123")
	issuerDID := did.MustParseDID("did:web:issuer.test:iam:456")
	redirectURI := "https://test.test/iam/123/cb"
	authServer := "https://auth.server"
	tokenEndpoint := authServer + "/token"
	cNonce := crypto.GenerateNonce()
	credEndpoint := authServer + "/credz"
	pkceParams := generatePKCEParams()
	code := "code"
	state := "state"
	accessToken := "access_token"
	verifiableCredential := createIssuerCredential(issuerDID, holderDID)
	redirectUrl := "https://client.service/issuance_is_done"

	session := Oid4vciSession{
		HolderDid:                &holderDID,
		IssuerDid:                &issuerDID,
		RemoteRedirectUri:        redirectUrl,
		RedirectUri:              redirectURI,
		PKCEParams:               pkceParams,
		IssuerTokenEndpoint:      tokenEndpoint,
		IssuerCredentialEndpoint: credEndpoint,
	}
	tokenResponse := oauth.Oid4vciTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		CNonce:      &cNonce,
	}
	credentialResponse := iam.CredentialResponse{
		Format:     "jwt_vc",
		Credential: verifiableCredential.Raw(),
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.client.storageEngine.GetSessionDatabase().GetStore(15*time.Minute, "oid4vci").Put(state, &session)
		ctx.iamClient.EXPECT().AccessTokenOid4vci(nil, holderDID.String(), tokenEndpoint, redirectURI, code, &pkceParams.Verifier).Return(&tokenResponse, nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, &cNonce, holderDID, issuerDID).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:  code,
				State: state,
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, callback)
		actual := callback.(CallbackOid4vciCredentialIssuance302Response)
		assert.Equal(t, redirectUrl, actual.Headers.Location)
	})
	t.Run("error_on_redirect", func(t *testing.T) {
		ctx := newTestClient(t)

		ctx.client.storageEngine.GetSessionDatabase().GetStore(15*time.Minute, "oid4vci").Put(state, &session)
		errorCode := "failed"
		errorDesc := "errorDesc"
		callback, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:             "",
				State:            state,
				Error:            &errorCode,
				ErrorDescription: &errorDesc,
			},
		})
		require.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, fmt.Sprintf("%s - %s", errorCode, errorDesc), err.Error())
	})
	t.Run("no_session", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:  code,
				State: state,
			},
		})
		require.Error(t, err)
	})
	t.Run("fail_access_token", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.client.storageEngine.GetSessionDatabase().GetStore(15*time.Minute, "oid4vci").Put(state, &session)
		ctx.iamClient.EXPECT().AccessTokenOid4vci(nil, holderDID.String(), tokenEndpoint, redirectURI, code, &pkceParams.Verifier).Return(nil, errors.New("FAIL"))
		//ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, holderDID, issuerDID).Return(&credentialResponse, nil)
		//ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil)
		//ctx.wallet.EXPECT().Put(nil, *verifiableCredential)

		callback, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:  code,
				State: state,
			},
		})
		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "access_denied - error while fetching the access_token from endpoint: https://auth.server/token, error : FAIL", err.Error())
	})
	t.Run("fail_credential_response", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.client.storageEngine.GetSessionDatabase().GetStore(15*time.Minute, "oid4vci").Put(state, &session)
		ctx.iamClient.EXPECT().AccessTokenOid4vci(nil, holderDID.String(), tokenEndpoint, redirectURI, code, &pkceParams.Verifier).Return(&tokenResponse, nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, &cNonce, holderDID, issuerDID).Return(nil, errors.New("FAIL"))

		callback, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:  code,
				State: state,
			},
		})
		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "server_error - error while fetching the credential from endpoint https://auth.server/credz, error : FAIL", err.Error())

	})
	t.Run("fail_verify", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.client.storageEngine.GetSessionDatabase().GetStore(15*time.Minute, "oid4vci").Put(state, &session)
		ctx.iamClient.EXPECT().AccessTokenOid4vci(nil, holderDID.String(), tokenEndpoint, redirectURI, code, &pkceParams.Verifier).Return(&tokenResponse, nil)
		ctx.iamClient.EXPECT().VerifiableCredentials(nil, credEndpoint, accessToken, &cNonce, holderDID, issuerDID).Return(&credentialResponse, nil)
		ctx.vcVerifier.EXPECT().Verify(*verifiableCredential, true, true, nil).Return(errors.New("FAIL"))

		callback, err := ctx.client.CallbackOid4vciCredentialIssuance(nil, CallbackOid4vciCredentialIssuanceRequestObject{
			Params: CallbackOid4vciCredentialIssuanceParams{
				Code:  code,
				State: state,
			},
		})
		assert.Error(t, err)
		assert.Nil(t, callback)
		assert.Equal(t, "server_error - error while verifying the credential from issuer: did:web:issuer.test:iam:456, error : FAIL", err.Error())

	})
}

func errorFromUrl(location string) string {
	parsedUrl, err := url.Parse(location)
	if err != nil {
		return ""
	}
	query := parsedUrl.Query()
	if query.Has("error") {
		return query.Get("error")
	}
	return ""
}

func createIssuerCredential(issuerDID did.DID, holderDID did.DID) *vc.VerifiableCredential {
	vmId := did.DIDURL{
		DID:             issuerDID,
		Fragment:        "key",
		DecodedFragment: "key",
	}
	kid := vmId.String()
	key := crypto.NewTestKey(kid)
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

func requestContext(queryParams map[string]interface{}) context.Context {
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
	return context.WithValue(audit.TestContext(), httpRequestContextKey, httpRequest)
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
	policy        *policy.MockPDPBackend
	resolver      *resolver.MockDIDResolver
	relyingParty  *oauthServices.MockRelyingParty
	vcr           *vcr.MockVCR
	vdr           *vdr.MockVDR
	vcIssuer      *issuer.MockIssuer
	vcVerifier    *verifier.MockVerifier
	wallet        *holder.MockWallet
}

func newTestClient(t testing.TB) *testCtx {
	publicURL, err := url.Parse("https://example.com")
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	storageEngine := storage.NewTestStorageEngine(t)
	authnServices := auth.NewMockAuthenticationServices(ctrl)
	authnServices.EXPECT().PublicURL().Return(publicURL).AnyTimes()
	policyInstance := policy.NewMockPDPBackend(ctrl)
	mockResolver := resolver.NewMockDIDResolver(ctrl)
	relyingPary := oauthServices.NewMockRelyingParty(ctrl)
	vcIssuer := issuer.NewMockIssuer(ctrl)
	vcVerifier := verifier.NewMockVerifier(ctrl)
	iamClient := iam.NewMockClient(ctrl)
	mockVDR := vdr.NewMockVDR(ctrl)
	mockVCR := vcr.NewMockVCR(ctrl)
	mockWallet := holder.NewMockWallet(ctrl)

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
		client: &Wrapper{
			auth:          authnServices,
			vdr:           mockVDR,
			vcr:           mockVCR,
			storageEngine: storageEngine,
			policyBackend: policyInstance,
		},
	}
}
