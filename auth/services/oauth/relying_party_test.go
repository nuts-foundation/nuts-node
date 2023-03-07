/*
* Nuts node
* Copyright (C) 2021 Nuts community
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
 */

package oauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelyingParty_RequestAccessToken(t *testing.T) {
	const bearerToken = "jwt-bearer-token"

	t.Run("ok", func(t *testing.T) {
		ctx := createRPContext(t)
		httpHandler := &http2.Handler{
			StatusCode: http.StatusOK,
		}
		httpServer := httptest.NewServer(httpHandler)
		t.Cleanup(httpServer.Close)

		response, err := ctx.relyingParty.RequestAccessToken(context.Background(), bearerToken, httpServer.URL)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "nuts-node-refimpl/unknown", httpHandler.RequestHeaders.Get("User-Agent"))
	})
	t.Run("returns error when HTTP create access token fails", func(t *testing.T) {
		ctx := createRPContext(t)
		server := httptest.NewServer(&http2.Handler{
			StatusCode: http.StatusBadGateway,
		})
		t.Cleanup(server.Close)

		response, err := ctx.relyingParty.RequestAccessToken(context.Background(), bearerToken, server.URL)

		assert.Nil(t, response)
		assert.EqualError(t, err, "remote server/nuts node returned error creating access token: server returned HTTP 502 (expected: 200)")
	})

	t.Run("endpoint security validation (only HTTPS in strict mode)", func(t *testing.T) {
		ctx := createRPContext(t)
		httpServer := httptest.NewServer(&http2.Handler{
			StatusCode: http.StatusOK,
		})
		httpsServer := httptest.NewTLSServer(&http2.Handler{
			StatusCode: http.StatusOK,
		})
		t.Cleanup(httpServer.Close)
		t.Cleanup(httpsServer.Close)

		t.Run("HTTPS in strict mode", func(t *testing.T) {
			ctx.relyingParty.secureMode = true

			response, err := ctx.relyingParty.RequestAccessToken(context.Background(), bearerToken, httpsServer.URL)

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP allowed in non-strict mode", func(t *testing.T) {
			ctx.relyingParty.secureMode = false

			response, err := ctx.relyingParty.RequestAccessToken(context.Background(), bearerToken, httpServer.URL)

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP not allowed in strict mode", func(t *testing.T) {
			ctx.relyingParty.secureMode = true

			response, err := ctx.relyingParty.RequestAccessToken(context.Background(), bearerToken, httpServer.URL)

			assert.EqualError(t, err, fmt.Sprintf("authorization server endpoint must be HTTPS when in strict mode: %s", httpServer.URL))
			assert.Nil(t, response)
		})
	})
}

func TestService_CreateJwtBearerToken(t *testing.T) {
	usi := vc.VerifiablePresentation{}

	request := services.CreateJwtGrantRequest{
		Authorizer: authorizerDID.String(),
		Requester:  requesterDID.String(),
		IdentityVP: &usi,
		Service:    expectedService,
	}

	id := vdr.TestDIDA.URI()
	id.Fragment = "1"
	validCredential := vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
		ID:           &id,
		Type:         []ssi.URI{*credential.NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:       vdr.TestDIDA.URI(),
		IssuanceDate: time.Now(),
		CredentialSubject: []interface{}{credential.NutsAuthorizationCredentialSubject{
			ID:           vdr.TestDIDB.String(),
			PurposeOfUse: "eTransfer",
			Resources: []credential.Resource{
				{
					Path:        "/composition/1",
					Operations:  []string{"read"},
					UserContext: true,
				},
			},
		}},
		Proof: []interface{}{vc.Proof{}},
	}

	t.Run("create a JwtBearerToken", func(t *testing.T) {
		ctx := createRPContext(t)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(requesterDID, gomock.Any()).MinTimes(1).Return(requesterSigningKeyID.String(), nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), requesterSigningKeyID.String()).Return("token", nil)

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		require.Nil(t, err)
		require.NotEmpty(t, token.BearerToken)

		assert.Equal(t, "token", token.BearerToken)
		assert.Equal(t, expectedAudience, token.AuthorizationServerEndpoint)
	})

	t.Run("create a JwtBearerToken with valid credentials", func(t *testing.T) {
		ctx := createRPContext(t)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(requesterDID, gomock.Any()).MinTimes(1).Return(requesterSigningKeyID.String(), nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), requesterSigningKeyID.String()).Return("token", nil)

		validRequest := request
		validRequest.Credentials = []vc.VerifiableCredential{validCredential}

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, validRequest)

		require.NoError(t, err)
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("create a JwtBearerToken with invalid credentials fails", func(t *testing.T) {
		ctx := createRPContext(t)

		invalidCredential := validCredential
		invalidCredential.Type = []ssi.URI{}

		invalidRequest := request
		invalidRequest.Credentials = []vc.VerifiableCredential{invalidCredential}

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, invalidRequest)

		assert.Error(t, err)
		assert.Empty(t, token)
	})

	t.Run("authorizer without endpoint", func(t *testing.T) {
		ctx := createRPContext(t)
		document := getAuthorizerDIDDocument()
		document.Service = []did.Service{}

		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return("", types.ErrServiceNotFound)

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Empty(t, token)
		assert.ErrorIs(t, err, types.ErrServiceNotFound)
	})

	t.Run("request without authorizer", func(t *testing.T) {
		ctx := createRPContext(t)

		request := services.CreateJwtGrantRequest{
			Requester:  requesterDID.String(),
			IdentityVP: &usi,
		}

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createRPContext(t)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(requesterDID, gomock.Any()).MinTimes(1).Return(requesterSigningKeyID.String(), nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), requesterSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})
}

func TestRelyingParty_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		ctx := createRPContext(t)

		ctx.relyingParty.Configure(true)

		assert.True(t, ctx.relyingParty.secureMode)
	})
}

type rpTestContext struct {
	ctrl            *gomock.Controller
	keyStore        *crypto.MockKeyStore
	didResolver     *didstore.MockStore
	keyResolver     *types.MockKeyResolver
	serviceResolver *didman.MockCompoundServiceResolver
	relyingParty    *relyingParty
	audit           context.Context
}

var createRPContext = func(t *testing.T) *rpTestContext {
	ctrl := gomock.NewController(t)

	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	serviceResolver := didman.NewMockCompoundServiceResolver(ctrl)
	didResolver := didstore.NewMockStore(ctrl)

	return &rpTestContext{
		ctrl:            ctrl,
		keyStore:        privateKeyStore,
		keyResolver:     keyResolver,
		serviceResolver: serviceResolver,
		didResolver:     didResolver,
		relyingParty: &relyingParty{
			keyResolver:     keyResolver,
			privateKeyStore: privateKeyStore,
			serviceResolver: serviceResolver,
			httpClientTLS: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		audit: audit.TestContext(),
	}
}
