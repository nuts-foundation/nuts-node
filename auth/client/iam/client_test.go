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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"net/http"
	"net/http/httptest"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestIAMClient_AccessToken(t *testing.T) {
	code := "code"
	callbackURI := "https://test.test/iam/123/callback"
	clientID := did.MustParseDID("did:web:test.test:iam:123")

	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.verifierDID, callbackURI, clientID)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("error - failed to get access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.token = nil

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.verifierDID, callbackURI, clientID)

		assert.EqualError(t, err, "remote server: error creating access token: server returned HTTP 404 (expected: 200)")
		assert.Nil(t, response)
	})
}

func TestIAMClient_ClientMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/.well-known/oauth-authorization-server", ctx.tlsServer.URL)

		clientMetadata, err := ctx.client.ClientMetadata(ctx.audit, endpoint)

		require.NoError(t, err)
		assert.NotNil(t, clientMetadata)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/.well-known/oauth-authorization-server", ctx.tlsServer.URL)
		ctx.metadata = nil

		clientMetadata, err := ctx.client.ClientMetadata(ctx.audit, endpoint)

		assert.Error(t, err)
		assert.Nil(t, clientMetadata)
	})
}

func TestIAMClient_PostError(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/error", ctx.tlsServer.URL)
		oauthError := oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "missing required parameter",
		}

		redirect, err := ctx.client.PostError(ctx.audit, oauthError, endpoint, "state")

		require.NoError(t, err)
		assert.Equal(t, "redirect", redirect)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/error", ctx.tlsServer.URL)
		ctx.errorResponse = nil

		redirect, err := ctx.client.PostError(ctx.audit, oauth.OAuth2Error{}, endpoint, "state")

		assert.Error(t, err)
		assert.Empty(t, redirect)
	})
}

func TestIAMClient_PostResponse(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/response", ctx.tlsServer.URL)
		vp := vc.VerifiablePresentation{Type: []ssi.URI{ssi.MustParseURI("VerifiablePresentation")}}
		// marshal and unmarshal to make sure Raw() works
		bytes, _ := json.Marshal(vp)
		_ = json.Unmarshal(bytes, &vp)

		redirect, err := ctx.client.PostAuthorizationResponse(
			ctx.audit,
			vp,
			pe.PresentationSubmission{Id: "id"},
			endpoint,
			"state",
		)

		require.NoError(t, err)
		assert.Equal(t, "redirect", redirect)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/response", ctx.tlsServer.URL)
		ctx.response = nil

		redirect, err := ctx.client.PostAuthorizationResponse(ctx.audit, vc.VerifiablePresentation{}, pe.PresentationSubmission{}, endpoint, "")

		assert.Error(t, err)
		assert.Empty(t, redirect)
	})
}

func TestIAMClient_PresentationDefinition(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/presentation_definition", ctx.tlsServer.URL)

		pd, err := ctx.client.PresentationDefinition(context.Background(), endpoint)

		assert.NoError(t, err)
		assert.NotNil(t, pd)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		endpoint := fmt.Sprintf("%s/presentation_definition", ctx.tlsServer.URL)
		ctx.presentationDefinition = nil

		pd, err := ctx.client.PresentationDefinition(context.Background(), endpoint)

		assert.Error(t, err)
		assert.Nil(t, pd)
	})
}

func TestIAMClient_AuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		metadata, err := ctx.client.AuthorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, *ctx.authzServerMetadata, *metadata)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = nil

		_, err := ctx.client.AuthorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
}

func TestIAMClient_AuthorizationRequest(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	scopes := "first second"
	clientState := crypto.GenerateNonce()

	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		redirectURL, err := ctx.client.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.NoError(t, err)
		require.NotNil(t, redirectURL)
		assert.Equal(t, walletDID.String(), redirectURL.Query().Get("client_id"))
		assert.Equal(t, "code", redirectURL.Query().Get("response_type"))
		assert.Equal(t, "first second", redirectURL.Query().Get("scope"))
		assert.NotEmpty(t, redirectURL.Query().Get("state"))
		assert.Equal(t, "https://test.test/iam/123/callback", redirectURL.Query().Get("redirect_uri"))
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = nil

		_, err := ctx.client.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - faulty authorization server metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{"))
		}

		_, err := ctx.client.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: unable to unmarshal response: unexpected end of JSON input, {")
	})
	t.Run("error - missing authorization endpoint", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.authzServerMetadata.AuthorizationEndpoint = ""

		_, err := ctx.client.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "no authorization endpoint found in metadata for")
	})
}

func TestRelyingParty_RequestRFC021AccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	scopes := "first second"

	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), walletDID, gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any(), ctx.verifierDID.URI()).Return(&vc.VerifiablePresentation{}, &pe.PresentationSubmission{}, nil)

		response, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("error - access denied", func(t *testing.T) {
		oauthError := oauth.OAuth2Error{
			Code:        "invalid_scope",
			Description: "the scope you requested is unknown",
		}
		oauthErrorBytes, _ := json.Marshal(oauthError)
		ctx := createClientServerTestContext(t)
		ctx.token = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(oauthErrorBytes)
		}
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), walletDID, gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any(), ctx.verifierDID.URI()).Return(&vc.VerifiablePresentation{}, &pe.PresentationSubmission{}, nil)

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		require.Error(t, err)
		oauthError, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidScope, oauthError.Code)
	})
	t.Run("error - failed to get presentation definition", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.presentationDefinition = nil

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = nil

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - faulty presentation definition", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.presentationDefinition = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{"))
		}

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: unable to unmarshal response: unexpected end of JSON input")
	})
	t.Run("error - failed to build vp", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), walletDID, gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any(), ctx.verifierDID.URI()).Return(nil, nil, assert.AnError)

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
	})
}

func createClientTestContext(t *testing.T, tlsConfig *tls.Config) *clientTestContext {
	ctrl := gomock.NewController(t)
	wallet := holder.NewMockWallet(ctrl)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.InsecureSkipVerify = true

	return &clientTestContext{
		audit: audit.TestContext(),
		ctrl:  ctrl,
		client: &IAMClient{
			httpClientTLS: tlsConfig,
			wallet:        wallet,
		},
		wallet: wallet,
	}
}

type clientTestContext struct {
	ctrl   *gomock.Controller
	audit  context.Context
	client Client
	wallet *holder.MockWallet
}

type clientServerTestContext struct {
	*clientTestContext
	authzServerMetadata    *oauth.AuthorizationServerMetadata
	handler                http.HandlerFunc
	tlsServer              *httptest.Server
	verifierDID            did.DID
	errorResponse          func(writer http.ResponseWriter)
	metadata               func(writer http.ResponseWriter)
	presentationDefinition func(writer http.ResponseWriter)
	response               func(writer http.ResponseWriter)
	token                  func(writer http.ResponseWriter)
}

func createClientServerTestContext(t *testing.T) *clientServerTestContext {
	metadata := &oauth.AuthorizationServerMetadata{VPFormats: oauth.DefaultOpenIDSupportedFormats()}
	ctx := &clientServerTestContext{
		clientTestContext: createClientTestContext(t, nil),
		metadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(*metadata)
			_, _ = writer.Write(bytes)
			return
		},
		errorResponse: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(oauth.Redirect{
				RedirectURI: "redirect",
			})
			_, _ = writer.Write(bytes)
			return
		},
		presentationDefinition: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(pe.PresentationDefinition{})
			_, _ = writer.Write(bytes)
			return
		},
		response: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(oauth.Redirect{
				RedirectURI: "redirect",
			})
			_, _ = writer.Write(bytes)
			return
		},
		token: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"access_token": "token", "token_type": "bearer"}`))
			return
		},
	}

	ctx.handler = func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/oauth-authorization-server":
			if ctx.metadata != nil {
				ctx.metadata(writer)
				return
			}
		case "/error":
			if ctx.errorResponse != nil {
				assert.Equal(t, string(oauth.InvalidRequest), request.FormValue("error"))
				ctx.errorResponse(writer)
				return
			}
		case "/presentation_definition":
			if ctx.presentationDefinition != nil {
				ctx.presentationDefinition(writer)
				return
			}
		case "/response":
			if ctx.response != nil {
				assert.NotEmpty(t, request.FormValue(oauth.VpTokenParam))
				assert.NotEmpty(t, request.FormValue(oauth.PresentationSubmissionParam))
				assert.NotEmpty(t, request.FormValue(oauth.StateParam))
				ctx.errorResponse(writer)
				return
			}
		case "/token":
			if ctx.token != nil {
				ctx.token(writer)
				return
			}
		}
		writer.WriteHeader(http.StatusNotFound)
	}
	ctx.tlsServer = http2.TestTLSServer(t, ctx.handler)
	ctx.verifierDID = didweb.ServerURLToDIDWeb(t, ctx.tlsServer.URL)
	ctx.authzServerMetadata = metadata
	ctx.authzServerMetadata.TokenEndpoint = ctx.tlsServer.URL + "/token"
	ctx.authzServerMetadata.PresentationDefinitionEndpoint = ctx.tlsServer.URL + "/presentation_definition"
	ctx.authzServerMetadata.AuthorizationEndpoint = ctx.tlsServer.URL + "/authorize"

	return ctx
}
