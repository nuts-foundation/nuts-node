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
	"github.com/nuts-foundation/nuts-node/http/client"
	test2 "github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestIAMClient_AccessToken(t *testing.T) {
	code := "code"
	callbackURI := "https://test.test/iam/123/callback"
	clientID := did.MustParseDID("did:web:test.test:iam:123")
	codeVerifier := "code_verifier"
	kid := "did:web:test.test:iam:123#1"

	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.authzServerMetadata.TokenEndpoint, callbackURI, clientID, codeVerifier, false)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("ok - with DPoP", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.keyResolver.EXPECT().ResolveKey(clientID, nil, resolver.NutsSigningKeyType).Return(kid, nil, nil)
		ctx.jwtSigner.EXPECT().SignDPoP(context.Background(), gomock.Any(), kid).Return("dpop", nil)

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.authzServerMetadata.TokenEndpoint, callbackURI, clientID, codeVerifier, true)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("error - failed to get access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.token = nil

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.authzServerMetadata.TokenEndpoint, callbackURI, clientID, codeVerifier, false)

		assert.EqualError(t, err, "remote server: error creating access token: server returned HTTP 404 (expected: 200)")
		assert.Nil(t, response)
	})
	t.Run("error - failed to create DPoP header", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.keyResolver.EXPECT().ResolveKey(clientID, nil, resolver.NutsSigningKeyType).Return(kid, nil, nil)
		ctx.jwtSigner.EXPECT().SignDPoP(context.Background(), gomock.Any(), kid).Return("", assert.AnError)

		response, err := ctx.client.AccessToken(context.Background(), code, ctx.authzServerMetadata.TokenEndpoint, callbackURI, clientID, codeVerifier, true)

		assert.Error(t, err)
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
	t.Run("insecure", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		pd, err := ctx.client.PresentationDefinition(context.Background(), "http://example.com/presentation_definition")

		assert.Error(t, err)
		assert.Nil(t, pd)
	})
}

func TestIAMClient_AuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		metadata, err := ctx.client.AuthorizationServerMetadata(context.Background(), ctx.tlsServer.URL)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, *ctx.authzServerMetadata, *metadata)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = nil

		_, err := ctx.client.AuthorizationServerMetadata(context.Background(), ctx.tlsServer.URL)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
}

func TestRelyingParty_RequestRFC021AccessToken(t *testing.T) {
	const subjectID = "subby"
	primaryWalletDID := did.MustParseDID("did:primary:123")
	secondaryWalletDID := did.MustParseDID("did:secondary:123")
	primaryKID := "did:primary:123#1"
	scopes := "first second"
	holderURI := primaryWalletDID.URI()
	createdVP := &vc.VerifiablePresentation{
		Holder: &holderURI,
	}

	t.Run("fulfills the Presentation Definition", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).Return(createdVP, &pe.PresentationSubmission{}, nil)

		response, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		assert.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("no DID fulfills the Presentation Definition", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).Return(nil, nil, holder.ErrNoCredentials)

		response, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		assert.ErrorIs(t, err, holder.ErrNoCredentials)
		assert.Nil(t, response)
	})
	t.Run("with additional credentials", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		credentials := []vc.VerifiableCredential{
			{
				Context: []ssi.URI{
					holder.VerifiableCredentialLDContextV1,
					credential.NutsV1ContextURI,
				},
				Type: []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("EmployeeCredential")},
				CredentialSubject: []interface{}{
					map[string]interface{}{
						"roleName":   "employee",
						"name":       "John Doe",
						"identifier": "123",
					},
				},
			},
		}
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []did.DID, additionalCredentials map[did.DID][]vc.VerifiableCredential, _ pe.PresentationDefinition, _ map[string]map[string][]string, _ holder.BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
				// Assert self-attested credentials
				require.Len(t, additionalCredentials, 2)
				require.Len(t, additionalCredentials[primaryWalletDID], 1)
				assert.Equal(t, primaryWalletDID.URI(), additionalCredentials[primaryWalletDID][0].Issuer)
				require.Len(t, additionalCredentials[secondaryWalletDID], 1)
				assert.Equal(t, secondaryWalletDID.URI(), additionalCredentials[secondaryWalletDID][0].Issuer)
				return createdVP, &pe.PresentationSubmission{}, nil
			})

		response, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, credentials)

		assert.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "token", response.AccessToken)
		assert.Equal(t, "bearer", response.TokenType)
	})
	t.Run("ok with DPoPHeader", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.keyResolver.EXPECT().ResolveKey(primaryWalletDID, nil, resolver.NutsSigningKeyType).Return(primaryKID, nil, nil)
		ctx.jwtSigner.EXPECT().SignDPoP(context.Background(), gomock.Any(), primaryKID).Return("dpop", nil)
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).Return(createdVP, &pe.PresentationSubmission{}, nil)

		response, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, true, nil)

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
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).Return(createdVP, &pe.PresentationSubmission{}, nil)

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		require.Error(t, err)
		oauthError, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidScope, oauthError.Code)
	})
	t.Run("error - failed to get presentation definition", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.presentationDefinition = nil

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: server returned HTTP 404 (expected: 200)")
	})
	t.Run("error - failed to get authorization server metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.metadata = nil

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

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

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve presentation definition: unable to unmarshal response: unexpected end of JSON input")
	})
	t.Run("error - failed to build vp", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), subjectID).Return([]did.DID{primaryWalletDID, secondaryWalletDID}, nil)
		ctx.wallet.EXPECT().BuildSubmission(gomock.Any(), []did.DID{primaryWalletDID, secondaryWalletDID}, gomock.Any(), gomock.Any(), oauth.DefaultOpenIDSupportedFormats(), gomock.Any()).Return(nil, nil, assert.AnError)

		_, err := ctx.client.RequestRFC021AccessToken(context.Background(), subjectID, ctx.verifierURL.String(), scopes, false, nil)

		assert.Error(t, err)
	})
}

func TestIAMClient_RequestObjectByGet(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		requestURI := ctx.tlsServer.URL + "/request.jwt"

		response, err := ctx.client.RequestObjectByGet(context.Background(), requestURI)

		require.NoError(t, err)
		assert.Equal(t, "Request Object", response)
	})
	t.Run("error - invalid request_uri", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		response, err := ctx.client.RequestObjectByGet(context.Background(), ":")

		assert.EqualError(t, err, "invalid request_uri: parse \":\": missing protocol scheme")
		assert.Empty(t, response)
	})
	t.Run("error - failed to get access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.requestObjectJWT = nil
		requestURI := ctx.tlsServer.URL + "/request.jwt"

		response, err := ctx.client.RequestObjectByGet(context.Background(), requestURI)

		assert.EqualError(t, err, "failed to retrieve JAR Request Object: server returned HTTP 404 (expected: 200)")
		assert.Empty(t, response)
	})
}

func TestIAMClient_RequestObjectByPost(t *testing.T) {
	metadata := oauth.AuthorizationServerMetadata{Issuer: "me"}
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		requestURI := ctx.tlsServer.URL + "/request.jwt"

		response, err := ctx.client.RequestObjectByPost(context.Background(), requestURI, metadata)

		require.NoError(t, err)
		assert.Equal(t, "Request Object", response)
	})
	t.Run("error - invalid request_uri", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		response, err := ctx.client.RequestObjectByPost(context.Background(), ":", metadata)

		assert.EqualError(t, err, "invalid request_uri: parse \":\": missing protocol scheme")
		assert.Empty(t, response)
	})
	t.Run("error - failed to get access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.requestObjectJWT = nil
		requestURI := ctx.tlsServer.URL + "/request.jwt"

		response, err := ctx.client.RequestObjectByPost(context.Background(), requestURI, metadata)

		assert.EqualError(t, err, "failed to retrieve JAR Request Object: server returned HTTP 404 (expected: 200)")
		assert.Empty(t, response)
	})
}

func createClientTestContext(t *testing.T, tlsConfig *tls.Config) *clientTestContext {
	ctrl := gomock.NewController(t)
	jwtSigner := crypto.NewMockJWTSigner(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	subjectManager := didsubject.NewMockSubjectManager(ctrl)
	wallet := holder.NewMockWallet(ctrl)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.InsecureSkipVerify = true

	return &clientTestContext{
		audit: audit.TestContext(),
		ctrl:  ctrl,
		client: &OpenID4VPClient{
			wallet:         wallet,
			subjectManager: subjectManager,
			httpClient: HTTPClient{
				strictMode: false,
				httpClient: client.NewWithTLSConfig(10*time.Second, tlsConfig),
			},
			jwtSigner:   jwtSigner,
			keyResolver: keyResolver,
		},
		jwtSigner:      jwtSigner,
		keyResolver:    keyResolver,
		wallet:         wallet,
		subjectManager: subjectManager,
	}
}

type clientTestContext struct {
	audit          context.Context
	client         Client
	ctrl           *gomock.Controller
	jwtSigner      *crypto.MockJWTSigner
	keyResolver    *resolver.MockKeyResolver
	wallet         *holder.MockWallet
	subjectManager *didsubject.MockSubjectManager
}

type clientServerTestContext struct {
	*clientTestContext
	authzServerMetadata            *oauth.AuthorizationServerMetadata
	openIDCredentialIssuerMetadata *oauth.OpenIDCredentialIssuerMetadata
	handler                        http.HandlerFunc
	tlsServer                      *httptest.Server
	verifierDID                    did.DID
	verifierURL                    *url.URL
	issuerDID                      did.DID
	errorResponse                  func(writer http.ResponseWriter)
	metadata                       func(writer http.ResponseWriter)
	credentialIssuerMetadata       func(writer http.ResponseWriter)
	presentationDefinition         func(writer http.ResponseWriter)
	response                       func(writer http.ResponseWriter)
	token                          func(writer http.ResponseWriter)
	credentials                    func(writer http.ResponseWriter)
	requestObjectJWT               func(writer http.ResponseWriter)
}

func createClientServerTestContext(t *testing.T) *clientServerTestContext {
	credentialIssuerMetadata := &oauth.OpenIDCredentialIssuerMetadata{}
	metadata := &oauth.AuthorizationServerMetadata{VPFormatsSupported: oauth.DefaultOpenIDSupportedFormats()}
	ctx := &clientServerTestContext{
		clientTestContext: createClientTestContext(t, nil),
		metadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(*metadata)
			_, _ = writer.Write(bytes)
			return
		},
		credentialIssuerMetadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(*credentialIssuerMetadata)
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
		credentials: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"format": "format", "credential": "credential"}`))
			return
		},
		requestObjectJWT: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/oauth-authz-req+jwt")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`Request Object`))
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
		case "/.well-known/openid-credential-issuer/issuer":
			if ctx.credentialIssuerMetadata != nil {
				ctx.credentialIssuerMetadata(writer)
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
		case "/credentials":
			if ctx.credentials != nil {
				ctx.credentials(writer)
				return
			}
		case "/request.jwt":
			if ctx.requestObjectJWT != nil {
				ctx.requestObjectJWT(writer)
				return
			}
		}
		writer.WriteHeader(http.StatusNotFound)
	}
	ctx.tlsServer = http2.TestTLSServer(t, ctx.handler)
	ctx.verifierDID = didweb.ServerURLToDIDWeb(t, ctx.tlsServer.URL)
	ctx.verifierURL = test2.MustParseURL(ctx.tlsServer.URL)
	ctx.issuerDID = didweb.ServerURLToDIDWeb(t, ctx.tlsServer.URL+"/issuer")
	ctx.authzServerMetadata = metadata
	ctx.authzServerMetadata.TokenEndpoint = ctx.tlsServer.URL + "/token"
	ctx.authzServerMetadata.PresentationDefinitionEndpoint = ctx.tlsServer.URL + "/presentation_definition"
	ctx.authzServerMetadata.AuthorizationEndpoint = ctx.tlsServer.URL + "/authorize"
	ctx.authzServerMetadata.RequireSignedRequestObject = true

	ctx.openIDCredentialIssuerMetadata = credentialIssuerMetadata
	ctx.openIDCredentialIssuerMetadata.AuthorizationServers = []string{ctx.authzServerMetadata.AuthorizationEndpoint}
	ctx.openIDCredentialIssuerMetadata.CredentialIssuer = "issuer"
	ctx.openIDCredentialIssuerMetadata.CredentialEndpoint = ctx.tlsServer.URL + "/credentials"

	return ctx
}

func TestIAMClient_OpenIdCredentialIssuerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		metadata, err := ctx.client.OpenIdCredentialIssuerMetadata(context.Background(), ctx.tlsServer.URL+"/issuer")

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, *ctx.openIDCredentialIssuerMetadata, *metadata)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := createClientServerTestContext(t)
		ctx.credentialIssuerMetadata = nil

		response, err := ctx.client.OpenIdCredentialIssuerMetadata(context.Background(), ctx.tlsServer.URL+"/issuer")

		require.Error(t, err)
		assert.Nil(t, response)
		assert.EqualError(t, err, "failed to retrieve Openid credential issuer metadata: server returned HTTP 404 (expected: 200)")
	})
}

func TestIAMClient_VerifiableCredentials(t *testing.T) {
	accessToken := "code"
	proowJWT := "top secret"

	t.Run("ok", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		response, err := ctx.client.VerifiableCredentials(context.Background(), ctx.openIDCredentialIssuerMetadata.CredentialEndpoint, accessToken, proowJWT)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "credential", response.Credential)
	})
	t.Run("error - failed to get access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		ctx.credentials = nil

		response, err := ctx.client.VerifiableCredentials(context.Background(), ctx.openIDCredentialIssuerMetadata.CredentialEndpoint, accessToken, proowJWT)

		assert.EqualError(t, err, "remote server: failed to retrieve credentials: server returned HTTP 404 (expected: 200)")
		assert.Nil(t, response)
	})
	t.Run("error - invalid access token", func(t *testing.T) {
		ctx := createClientServerTestContext(t)

		ctx.credentials = func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"format": "format", "credential": fail}`))
			return
		}

		response, err := ctx.client.VerifiableCredentials(context.Background(), ctx.openIDCredentialIssuerMetadata.CredentialEndpoint, accessToken, proowJWT)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}
