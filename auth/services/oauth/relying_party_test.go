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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	vcr "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestRelyingParty_RequestRFC003AccessToken(t *testing.T) {
	const bearerToken = "jwt-bearer-token"

	t.Run("ok", func(t *testing.T) {
		ctx := createRPContext(t, nil)
		httpHandler := &http2.Handler{
			StatusCode: http.StatusOK,
		}
		httpServer := httptest.NewServer(httpHandler)
		t.Cleanup(httpServer.Close)

		response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, mustParseURL(httpServer.URL))

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "nuts-node-refimpl/unknown", httpHandler.RequestHeaders.Get("User-Agent"))
	})
	t.Run("returns error when HTTP create access token fails", func(t *testing.T) {
		ctx := createRPContext(t, nil)
		server := httptest.NewServer(&http2.Handler{
			StatusCode: http.StatusBadGateway,
		})
		t.Cleanup(server.Close)

		response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, mustParseURL(server.URL))

		assert.Nil(t, response)
		assert.EqualError(t, err, "remote server/nuts node returned error creating access token: server returned HTTP 502 (expected: 200)")
	})

	t.Run("endpoint security validation (only HTTPS in strict mode)", func(t *testing.T) {
		ctx := createRPContext(t, nil)
		httpServer := httptest.NewServer(&http2.Handler{
			StatusCode: http.StatusOK,
		})
		httpsServer := httptest.NewTLSServer(&http2.Handler{
			StatusCode: http.StatusOK,
		})
		t.Cleanup(httpServer.Close)
		t.Cleanup(httpsServer.Close)

		t.Run("HTTPS in strict mode", func(t *testing.T) {
			ctx.relyingParty.strictMode = true

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, mustParseURL(httpsServer.URL))

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP allowed in non-strict mode", func(t *testing.T) {
			ctx.relyingParty.strictMode = false

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, mustParseURL(httpServer.URL))

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP not allowed in strict mode", func(t *testing.T) {
			ctx.relyingParty.strictMode = true

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, mustParseURL(httpServer.URL))

			assert.EqualError(t, err, fmt.Sprintf("authorization server endpoint must be HTTPS when in strict mode: %s", httpServer.URL))
			assert.Nil(t, response)
		})
	})
}

func TestRelyingParty_RequestRFC021AccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	scopes := []string{"first", "second"}

	t.Run("ok", func(t *testing.T) {
		authzServerMetadata := oauth.AuthorizationServerMetadata{}
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/did.json":
				writer.Header().Add("Content-Type", "application/did+json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("{}"))
				return
			case "/.well-known/oauth-authorization-server":
				writer.Header().Add("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				bytes, _ := json.Marshal(authzServerMetadata)
				_, _ = writer.Write(bytes)
				return
			case "/presentation-definitions":
				writer.Header().Add("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("[]"))
			default:
				writer.WriteHeader(http.StatusNotFound)
			}
		})
		tlsServer := http2.TestTLSServer(t, handler)
		verifierDID := didweb.ServerURLToDIDWeb(t, tlsServer.URL)
		authzServerMetadata.PresentationDefinitionEndpoint = tlsServer.URL + "/presentation-definitions"
		ctx := createRPContext(t, tlsServer.TLS)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return([]vcr.VerifiableCredential{}, nil)

		// todo, test PresentationDefinition that matches a test credential

		response, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, verifierDID, scopes)

		assert.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
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
		ctx := createRPContext(t, nil)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, types.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, requesterSigningKeyID.String()).Return("token", nil)

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		require.Nil(t, err)
		require.NotEmpty(t, token.BearerToken)

		assert.Equal(t, "token", token.BearerToken)
		assert.Equal(t, expectedAudience, token.AuthorizationServerEndpoint)
	})

	t.Run("create a JwtBearerToken with valid credentials", func(t *testing.T) {
		ctx := createRPContext(t, nil)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, types.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, requesterSigningKeyID.String()).Return("token", nil)

		validRequest := request
		validRequest.Credentials = []vc.VerifiableCredential{validCredential}

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, validRequest)

		require.NoError(t, err)
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("create a JwtBearerToken with invalid credentials fails", func(t *testing.T) {
		ctx := createRPContext(t, nil)

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
		ctx := createRPContext(t, nil)
		document := getAuthorizerDIDDocument()
		document.Service = []did.Service{}

		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return("", types.ErrServiceNotFound)

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Empty(t, token)
		assert.ErrorIs(t, err, types.ErrServiceNotFound)
	})

	t.Run("request without authorizer", func(t *testing.T) {
		ctx := createRPContext(t, nil)

		request := services.CreateJwtGrantRequest{
			Requester:  requesterDID.String(),
			IdentityVP: &usi,
		}

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createRPContext(t, nil)

		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(authorizerDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, types.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, requesterSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})
}

type rpTestContext struct {
	audit           context.Context
	ctrl            *gomock.Controller
	didResolver     *types.MockDIDResolver
	keyStore        *crypto.MockKeyStore
	keyResolver     *types.MockKeyResolver
	relyingParty    *relyingParty
	serviceResolver *didman.MockCompoundServiceResolver
	wallet          *holder.MockWallet
}

func createRPContext(t *testing.T, tlsConfig *tls.Config) *rpTestContext {
	ctrl := gomock.NewController(t)

	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	serviceResolver := didman.NewMockCompoundServiceResolver(ctrl)
	didResolver := types.NewMockDIDResolver(ctrl)
	wallet := holder.NewMockWallet(ctrl)

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.InsecureSkipVerify = true

	return &rpTestContext{
		audit:       audit.TestContext(),
		ctrl:        ctrl,
		didResolver: didResolver,
		keyStore:    privateKeyStore,
		keyResolver: keyResolver,
		relyingParty: &relyingParty{
			httpClientTLS:   tlsConfig,
			keyResolver:     keyResolver,
			privateKeyStore: privateKeyStore,
			serviceResolver: serviceResolver,
			wallet:          wallet,
		},
		serviceResolver: serviceResolver,
		wallet:          wallet,
	}
}

func mustParseURL(str string) url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return *u
}
