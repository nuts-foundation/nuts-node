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
	"github.com/nuts-foundation/nuts-node/test"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	vcr "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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

		response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, *test.MustParseURL(httpServer.URL))

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

		response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, *test.MustParseURL(server.URL))

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

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, *test.MustParseURL(httpsServer.URL))

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP allowed in non-strict mode", func(t *testing.T) {
			ctx.relyingParty.strictMode = false

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, *test.MustParseURL(httpServer.URL))

			assert.NoError(t, err)
			assert.NotNil(t, response)
		})
		t.Run("HTTP not allowed in strict mode", func(t *testing.T) {
			ctx.relyingParty.strictMode = true

			response, err := ctx.relyingParty.RequestRFC003AccessToken(context.Background(), bearerToken, *test.MustParseURL(httpServer.URL))

			assert.EqualError(t, err, fmt.Sprintf("authorization server endpoint must be HTTPS when in strict mode: %s", httpServer.URL))
			assert.Nil(t, response)
		})
	})
}

func TestRelyingParty_RequestRFC021AccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	scopes := "first second"
	credentials := []vcr.VerifiableCredential{credential.ValidNutsOrganizationCredential(t)}

	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), credentials, gomock.Any(), &walletDID, false).Return(&vc.VerifiablePresentation{}, nil).Return(&vc.VerifiablePresentation{}, nil)

		response, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("authorization server supported VP formats don't match", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.authzServerMetadata.VPFormats = map[string]map[string][]string{
			"unsupported": nil,
		}
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)

		response, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.EqualError(t, err, "requester, verifier (authorization server metadata) and presentation definition don't share a supported VP format")
		assert.Nil(t, response)
	})
	t.Run("error - access denied", func(t *testing.T) {
		oauthError := oauth.OAuth2Error{
			Code:        "invalid_scope",
			Description: "the scope you requested is unknown",
		}
		oauthErrorBytes, _ := json.Marshal(oauthError)
		ctx := createOAuthRPContext(t)
		ctx.token = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(oauthErrorBytes)
		}
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), credentials, gomock.Any(), &walletDID, false).Return(&vc.VerifiablePresentation{}, nil).Return(&vc.VerifiablePresentation{}, nil)

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		require.Error(t, err)
		oauthError, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidScope, oauthError.Code)
	})
	t.Run("error - no matching credentials", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return([]vc.VerifiableCredential{}, nil)

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		// the error should be a 412 precondition failed
		assert.EqualError(t, err, "no matching credentials")
	})
	t.Run("error - failed to get presentation definition", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.presentationDefinition = nil

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.metadata = nil

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - faulty presentation definition", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.presentationDefinition = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{"))
		}

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: unable to unmarshal response: unexpected end of JSON input")
	})
	t.Run("error - failed to build vp", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), credentials, gomock.Any(), &walletDID, false).Return(&vc.VerifiablePresentation{}, nil).Return(nil, errors.New("error"))

		_, err := ctx.relyingParty.RequestRFC021AccessToken(context.Background(), walletDID, ctx.verifierDID, scopes)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to create verifiable presentation: error")
	})
}

func TestRelyingParty_AuthorizationRequest(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	scopes := "first second"
	clientState := crypto.GenerateNonce()

	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthRPContext(t)

		redirectURL, err := ctx.relyingParty.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.NoError(t, err)
		require.NotNil(t, redirectURL)
		assert.Equal(t, walletDID.String(), redirectURL.Query().Get("client_id"))
		assert.Equal(t, "code", redirectURL.Query().Get("response_type"))
		assert.Equal(t, "first second", redirectURL.Query().Get("scope"))
		assert.NotEmpty(t, redirectURL.Query().Get("state"))
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.metadata = nil

		_, err := ctx.relyingParty.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - faulty authorization server metadata", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.metadata = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{"))
		}

		_, err := ctx.relyingParty.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: unable to unmarshal response: unexpected end of JSON input, {")
	})
	t.Run("error - missing authorization endpoint", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.authzServerMetadata.AuthorizationEndpoint = ""

		_, err := ctx.relyingParty.CreateAuthorizationRequest(context.Background(), walletDID, ctx.verifierDID, scopes, clientState)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "no authorization endpoint found in metadata for")
	})
}
func Test_chooseVPFormat(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		formats := map[string]map[string][]string{
			"jwt_vp": {
				"alg": {"ES256K"},
			},
		}

		format := chooseVPFormat(formats)

		assert.Equal(t, "jwt_vp", format)
	})
	t.Run("no supported format", func(t *testing.T) {
		formats := map[string]map[string][]string{}

		format := chooseVPFormat(formats)

		assert.Empty(t, format)
	})
	t.Run(" jwt_vp_json returns jwt_vp", func(t *testing.T) {
		formats := map[string]map[string][]string{
			"jwt_vp_json": {
				"alg": {"ES256K"},
			},
		}

		format := chooseVPFormat(formats)

		assert.Equal(t, "jwt_vp", format)
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
	issuanceDate := time.Now()
	validCredential := vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
		ID:           &id,
		Type:         []ssi.URI{*credential.NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:       vdr.TestDIDA.URI(),
		IssuanceDate: &issuanceDate,
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
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
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
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
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

		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return("", resolver.ErrServiceNotFound)

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Empty(t, token)
		assert.ErrorIs(t, err, resolver.ErrServiceNotFound)
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
		ctx.keyResolver.EXPECT().ResolveKey(requesterDID, nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKeyID, requesterSigningKey, nil)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, requesterSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.relyingParty.CreateJwtGrant(ctx.audit, request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})
}

func TestRelyingParty_authorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthRPContext(t)

		metadata, err := ctx.relyingParty.authorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, ctx.authzServerMetadata, *metadata)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := createOAuthRPContext(t)
		ctx.metadata = nil

		_, err := ctx.relyingParty.authorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
}

type rpTestContext struct {
	ctrl            *gomock.Controller
	keyStore        *crypto.MockKeyStore
	didResolver     *resolver.MockDIDResolver
	keyResolver     *resolver.MockKeyResolver
	serviceResolver *didman.MockCompoundServiceResolver
	relyingParty    *relyingParty
	audit           context.Context
	wallet          *holder.MockWallet
}

func createRPContext(t *testing.T, tlsConfig *tls.Config) *rpTestContext {
	ctrl := gomock.NewController(t)

	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	serviceResolver := didman.NewMockCompoundServiceResolver(ctrl)
	didResolver := resolver.NewMockDIDResolver(ctrl)
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

type rpOAuthTestContext struct {
	*rpTestContext
	authzServerMetadata    *oauth.AuthorizationServerMetadata
	handler                http.HandlerFunc
	tlsServer              *httptest.Server
	verifierDID            did.DID
	metadata               func(writer http.ResponseWriter)
	presentationDefinition func(writer http.ResponseWriter)
	token                  func(writer http.ResponseWriter)
}

func createOAuthRPContext(t *testing.T) *rpOAuthTestContext {
	presentationDefinition := `
{
  "input_descriptors": [
	{
	  "name": "Pick 1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.type"
			],
			"filter": {
			  "type": "string",
			  "const": "NutsOrganizationCredential"
			}
		  }
		]
	  }
    }	
  ]
}
`
	authzServerMetadata := &oauth.AuthorizationServerMetadata{VPFormats: oauth.DefaultOpenIDSupportedFormats()}
	ctx := &rpOAuthTestContext{
		rpTestContext: createRPContext(t, nil),
		metadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(*authzServerMetadata)
			_, _ = writer.Write(bytes)
			return
		},
		presentationDefinition: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(presentationDefinition))
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
		case "/presentation_definition":
			if ctx.presentationDefinition != nil {
				ctx.presentationDefinition(writer)
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
	authzServerMetadata.TokenEndpoint = ctx.tlsServer.URL + "/token"
	authzServerMetadata.PresentationDefinitionEndpoint = ctx.tlsServer.URL + "/presentation_definition"
	authzServerMetadata.AuthorizationEndpoint = ctx.tlsServer.URL + "/authorize"
	ctx.authzServerMetadata = authzServerMetadata

	return ctx
}
