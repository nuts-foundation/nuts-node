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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/url"
	"testing"
)

var holderDID = did.MustParseDID("did:web:example.com:holder")
var issuerDID = did.MustParseDID("did:web:example.com:issuer")

func TestWrapper_handleAuthorizeRequestFromHolder(t *testing.T) {
	defaultParams := func() map[string]string {
		return map[string]string{
			clientIDParam:     holderDID.String(),
			redirectURIParam:  "https://example.com",
			responseTypeParam: "code",
			scopeParam:        "test",
		}
	}

	t.Run("missing client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		delete(params, clientIDParam)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "missing client_id parameter")
	})
	t.Run("invalid client_id", func(t *testing.T) {
		ctx := newTestClient(t)
		params := defaultParams()
		params[clientIDParam] = "did:nuts:1"

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, params)

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid client_id parameter")
	})
	t.Run("error on authorization server metadata", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.relyingParty.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(nil, assert.AnError)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.ServerError, "failed to get authorization server metadata (holder)")
	})
	t.Run("failed to generate verifier web url", func(t *testing.T) {
		ctx := newTestClient(t)
		verifierDID := did.MustParseDID("did:notweb:example.com:verifier")
		ctx.relyingParty.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{}, nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.ServerError, "failed to translate own did to URL")
	})
	t.Run("incorrect holder AuthorizationEndpoint URL", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.relyingParty.EXPECT().AuthorizationServerMetadata(gomock.Any(), holderDID).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint: "://example.com",
		}, nil)

		_, err := ctx.client.handleAuthorizeRequestFromHolder(context.Background(), verifierDID, defaultParams())

		requireOAuthError(t, err, oauth.InvalidRequest, "invalid authorization_endpoint (holder)")
	})
}

func TestWrapper_sendPresentationRequest(t *testing.T) {
	instance := New(nil, nil, nil, nil)

	redirectURI, _ := url.Parse("https://example.com/redirect")
	verifierID, _ := url.Parse("https://example.com/verifier")
	walletID, _ := url.Parse("https://example.com/wallet")

	httpResponse := &stubResponseWriter{}

	err := instance.sendPresentationRequest(context.Background(), httpResponse, "test-scope", *redirectURI, *verifierID, *walletID)

	require.NoError(t, err)
	require.Equal(t, http.StatusFound, httpResponse.statusCode)
	location := httpResponse.headers.Get("Location")
	require.NotEmpty(t, location)
	locationURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "https", locationURL.Scheme)
	assert.Equal(t, "example.com", locationURL.Host)
	assert.Equal(t, "/wallet/authorize", locationURL.Path)
	assert.Equal(t, "test-scope", locationURL.Query().Get("scope"))
	assert.Equal(t, "vp_token id_token", locationURL.Query().Get("response_type"))
	assert.Equal(t, "direct_post", locationURL.Query().Get("response_mode"))
	assert.Equal(t, "https://example.com/verifier/.well-known/openid-wallet-metadata/metadata.xml", locationURL.Query().Get("client_metadata_uri"))
}

func TestWrapper_handlePresentationRequest(t *testing.T) {
	credentialID, _ := ssi.ParseURI("did:web:example.com:issuer#6AF53584-3337-4766-8C8D-0BFD54F6E527")
	walletCredentials := []vc.VerifiableCredential{
		{
			Context: []ssi.URI{
				vc.VCContextV1URI(),
				credential.NutsV1ContextURI,
			},
			ID:     credentialID,
			Issuer: issuerDID.URI(),
			Type:   []ssi.URI{vc.VerifiableCredentialTypeV1URI(), *credential.NutsOrganizationCredentialTypeURI},
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": holderDID.URI(),
					"organization": map[string]interface{}{
						"name": "Test Organization",
						"city": "Test City",
					},
				},
			},
		},
	}
	t.Run("with scope", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockVDR := vdr.NewMockVDR(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockWallet := holder.NewMockWallet(ctrl)
		mockVCR.EXPECT().Wallet().Return(mockWallet)
		mockAuth := auth.NewMockAuthenticationServices(ctrl)
		mockAuth.EXPECT().PresentationDefinitions().Return(pe.TestDefinitionResolver(t))
		mockWallet.EXPECT().List(gomock.Any(), holderDID).Return(walletCredentials, nil)
		mockVDR.EXPECT().IsOwner(gomock.Any(), holderDID).Return(true, nil)
		instance := New(mockAuth, mockVCR, mockVDR, storage.NewTestStorageEngine(t))

		params := map[string]string{
			"scope":               "eOverdracht-overdrachtsbericht",
			"response_type":       "code",
			"response_mode":       "direct_post",
			"client_metadata_uri": "https://example.com/client_metadata.xml",
		}

		response, err := instance.handlePresentationRequest(params, createSession(params, holderDID))

		require.NoError(t, err)
		httpResponse := &stubResponseWriter{}
		_ = response.VisitHandleAuthorizeRequestResponse(httpResponse)
		require.Equal(t, http.StatusOK, httpResponse.statusCode)
		assert.Contains(t, httpResponse.body.String(), "</html>")
	})
	t.Run("unsupported scope", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		peStore := &pe.DefinitionResolver{}
		_ = peStore.LoadFromFile("test/presentation_definition_mapping.json")
		mockAuth := auth.NewMockAuthenticationServices(ctrl)
		mockAuth.EXPECT().PresentationDefinitions().Return(peStore)
		instance := New(mockAuth, nil, nil, nil)

		params := map[string]string{
			"scope":               "unsupported",
			"response_type":       "code",
			"response_mode":       "direct_post",
			"client_metadata_uri": "https://example.com/client_metadata.xml",
		}

		response, err := instance.handlePresentationRequest(params, createSession(params, holderDID))

		requireOAuthError(t, err, oauth.InvalidRequest, "unsupported scope for presentation exchange: unsupported")
		assert.Nil(t, response)
	})
	t.Run("invalid response_mode", func(t *testing.T) {
		instance := New(nil, nil, nil, nil)
		params := map[string]string{
			"scope":               "eOverdracht-overdrachtsbericht",
			"response_type":       "code",
			"response_mode":       "invalid",
			"client_metadata_uri": "https://example.com/client_metadata.xml",
		}

		response, err := instance.handlePresentationRequest(params, createSession(params, holderDID))

		requireOAuthError(t, err, oauth.InvalidRequest, "response_mode must be direct_post")
		assert.Nil(t, response)
	})
}

type stubResponseWriter struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func (s *stubResponseWriter) Header() http.Header {
	if s.headers == nil {
		s.headers = make(http.Header)
	}
	return s.headers

}

func (s *stubResponseWriter) Write(i []byte) (int, error) {
	if s.body == nil {
		s.body = new(bytes.Buffer)
	}
	return s.body.Write(i)
}

func (s *stubResponseWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
}
