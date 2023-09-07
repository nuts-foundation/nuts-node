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

package v1

import (
	"context"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	pkg2 "github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"
)

type TestContext struct {
	ctrl                  *gomock.Controller
	authMock              pkg2.AuthenticationServices
	notaryMock            *services.MockContractNotary
	contractClientMock    *services.MockContractNotary
	authzServerMock       *oauth.MockAuthorizationServer
	relyingPartyMock      *oauth.MockRelyingParty
	wrapper               Wrapper
	cedentialResolverMock *vcr.MockResolver
	audit                 context.Context
}

type mockAuthClient struct {
	ctrl           *gomock.Controller
	contractNotary *services.MockContractNotary
	authzServer    *oauth.MockAuthorizationServer
	relyingParty   *oauth.MockRelyingParty
}

func (m *mockAuthClient) V2APIEnabled() bool {
	return true
}

func (m *mockAuthClient) AuthzServer() oauth.AuthorizationServer {
	return m.authzServer
}

func (m *mockAuthClient) RelyingParty() oauth.RelyingParty {
	return m.relyingParty
}

func (m *mockAuthClient) ContractNotary() services.ContractNotary {
	return m.contractNotary
}

func (m *mockAuthClient) PublicURL() *url.URL {
	return nil
}

func (m *mockAuthClient) PresentationDefinitions() *pe.DefinitionResolver {
	return &pe.DefinitionResolver{}
}

func createContext(t *testing.T) *TestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	contractNotary := services.NewMockContractNotary(ctrl)
	authzServer := oauth.NewMockAuthorizationServer(ctrl)
	relyingParty := oauth.NewMockRelyingParty(ctrl)
	mockCredentialResolver := vcr.NewMockResolver(ctrl)

	authMock := &mockAuthClient{
		ctrl:           ctrl,
		contractNotary: contractNotary,
		authzServer:    authzServer,
		relyingParty:   relyingParty,
	}

	requestCtx := audit.TestContext()

	return &TestContext{
		ctrl:                  ctrl,
		authMock:              authMock,
		notaryMock:            contractNotary,
		contractClientMock:    contractNotary,
		authzServerMock:       authzServer,
		relyingPartyMock:      relyingParty,
		cedentialResolverMock: mockCredentialResolver,
		wrapper:               Wrapper{Auth: authMock, CredentialResolver: mockCredentialResolver},
		audit:                 requestCtx,
	}
}

func TestWrapper_GetSignSessionStatus(t *testing.T) {
	signingSessionID := "123"
	sessionObj := GetSignSessionStatusRequestObject{SessionID: signingSessionID}
	t.Run("ok - started without VP", func(t *testing.T) {
		ctx := createContext(t)

		signingSessionStatus := "started"

		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		var vp interface{}
		signingSessionResult.EXPECT().VerifiablePresentation().Return(vp, nil)

		signingSessionResult.EXPECT().Status().Return(signingSessionStatus)

		ctx.contractClientMock.EXPECT().SigningSessionStatus(gomock.Any(), signingSessionID).Return(signingSessionResult, nil)

		expectedResponse := GetSignSessionStatus200JSONResponse{
			Status:                 signingSessionStatus,
			VerifiablePresentation: nil,
		}

		response, err := ctx.wrapper.GetSignSessionStatus(ctx.audit, sessionObj)
		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})

	t.Run("ok - completed with VP", func(t *testing.T) {
		ctx := createContext(t)
		signingSessionStatus := "completed"
		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)
		vp := vc.VerifiablePresentation{
			Context: []ssi.URI{vc.VCContextV1URI()},
		}
		signingSessionResult.EXPECT().VerifiablePresentation().Return(&vp, nil)
		signingSessionResult.EXPECT().Status().Return(signingSessionStatus)
		ctx.contractClientMock.EXPECT().SigningSessionStatus(gomock.Any(), signingSessionID).Return(signingSessionResult, nil)
		expectedResponse := GetSignSessionStatus200JSONResponse{
			Status: signingSessionStatus,
			VerifiablePresentation: &vc.VerifiablePresentation{
				Context: []ssi.URI{vc.VCContextV1URI()},
			},
		}

		response, err := ctx.wrapper.GetSignSessionStatus(ctx.audit, sessionObj)

		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})

	t.Run("nok - SigningSessionStatus returns error", func(t *testing.T) {
		ctx := createContext(t)

		ctx.contractClientMock.EXPECT().SigningSessionStatus(gomock.Any(), signingSessionID).Return(nil, services.ErrSessionNotFound)

		response, err := ctx.wrapper.GetSignSessionStatus(ctx.audit, sessionObj)

		assert.Nil(t, response)
		assert.ErrorIs(t, err, services.ErrSessionNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("nok - unable to build a VP", func(t *testing.T) {
		ctx := createContext(t)

		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		signingSessionResult.EXPECT().VerifiablePresentation().Return(nil, errors.New("missing key"))

		ctx.contractClientMock.EXPECT().SigningSessionStatus(gomock.Any(), signingSessionID).Return(signingSessionResult, nil)

		response, err := ctx.wrapper.GetSignSessionStatus(ctx.audit, sessionObj)

		assert.Nil(t, response)
		assert.EqualError(t, err, "error while building verifiable presentation: missing key")
	})
}

func TestWrapper_GetContractByType(t *testing.T) {
	t.Run("get known contact", func(t *testing.T) {
		ctx := createContext(t)

		cVersion := "v3"
		cLanguage := "EN"
		request := GetContractByTypeRequestObject{
			ContractType: "PractitionerLogin",
			Params: GetContractByTypeParams{
				Version:  &cVersion,
				Language: &cLanguage,
			},
		}

		a := contract.StandardContractTemplates.Get(contract.Type(request.ContractType), contract.Language(cLanguage), contract.Version(cVersion))
		expectedResponse := GetContractByType200JSONResponse{
			Language:           ContractLanguage(a.Language),
			Template:           &a.Template,
			TemplateAttributes: &a.TemplateAttributes,
			Type:               ContractType(a.Type),
			Version:            ContractVersion(a.Version),
		}

		response, err := ctx.wrapper.GetContractByType(ctx.audit, request)

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})

	t.Run("get an unknown contract", func(t *testing.T) {
		ctx := createContext(t)

		request := GetContractByTypeRequestObject{
			ContractType: "UnknownContract",
			Params:       GetContractByTypeParams{},
		}
		response, err := ctx.wrapper.GetContractByType(ctx.audit, request)

		assert.Nil(t, response)
		assert.ErrorIs(t, err, core.NotFoundError(""))
	})
}

func TestWrapper_DrawUpContract(t *testing.T) {

	t.Run("ok - it can draw up a standard contract", func(t *testing.T) {
		ctx := createContext(t)

		params := DrawUpContractRequest{
			Language:    "EN",
			Type:        "PractitionerLogin",
			Version:     "v3",
			LegalEntity: vdr.TestDIDA.String(),
		}

		template := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v3"]
		drawnUpContract := &contract.Contract{
			RawContractText: "drawn up contract text",
			Template:        template,
			Params:          nil,
		}
		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, *template, gomock.Any(), gomock.Any(), gomock.Any(), nil).Return(drawnUpContract, nil)

		expectedResponse := DrawUpContract200JSONResponse{
			Language: "EN",
			Message:  "drawn up contract text",
			Type:     "PractitionerLogin",
			Version:  "v3",
		}
		response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})
		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})

	t.Run("ok - it uses an OrganizationCredential", func(t *testing.T) {
		ctx := createContext(t)
		vcID := ssi.MustParseURI("did:nuts:1#1")
		vc := vc.VerifiableCredential{ID: &vcID}

		params := DrawUpContractRequest{
			Language:               "EN",
			Type:                   "PractitionerLogin",
			Version:                "v3",
			LegalEntity:            vdr.TestDIDA.String(),
			OrganizationCredential: &vc,
		}

		template := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v3"]
		drawnUpContract := &contract.Contract{
			RawContractText: "drawn up contract text",
			Template:        template,
			Params:          nil,
		}
		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, *template, gomock.Any(), gomock.Any(), gomock.Any(), &vc).Return(drawnUpContract, nil)

		expectedResponse := DrawUpContract200JSONResponse{
			Language: "EN",
			Message:  "drawn up contract text",
			Type:     "PractitionerLogin",
			Version:  "v3",
		}
		response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})
		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})

	t.Run("nok - wrong parameters", func(t *testing.T) {
		t.Run("invalid formatted validFrom", func(t *testing.T) {
			ctx := createContext(t)

			validFrom := "02 Jan 2010"

			params := DrawUpContractRequest{
				ValidFrom: &validFrom,
			}

			response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})

			assert.Nil(t, response)
			// only test for prefix due to some CI weirdness, see https://github.com/nuts-foundation/nuts-node/pull/1999.
			assert.ErrorContains(t, err, "could not parse validFrom")
			assert.ErrorIs(t, err, core.InvalidInputError(""))
		})

		t.Run("invalid formatted duration", func(t *testing.T) {
			ctx := createContext(t)

			duration := "15 minutes"

			params := DrawUpContractRequest{
				ValidDuration: &duration,
			}

			response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})

			assert.Nil(t, response)
			assert.ErrorIs(t, err, core.InvalidInputError(""))
			assert.EqualError(t, err, "could not parse validDuration: time: unknown unit \" minutes\" in duration \"15 minutes\"")
		})

		t.Run("unknown contract", func(t *testing.T) {
			ctx := createContext(t)

			params := DrawUpContractRequest{
				Language: "EN",
				Type:     "UnknownContractName",
				Version:  "v3",
			}

			response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})

			assert.Nil(t, response)
			assert.ErrorIs(t, err, core.NotFoundError(""))
			assert.EqualError(t, err, "no contract found for given combination of type, version, and language")
		})

		t.Run("malformed orgID", func(t *testing.T) {
			ctx := createContext(t)

			params := DrawUpContractRequest{
				Language:    "EN",
				Type:        "PractitionerLogin",
				Version:     "v3",
				LegalEntity: "ZorgId:15",
			}

			response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})

			assert.Nil(t, response)
			assert.ErrorIs(t, err, did.ErrInvalidDID)
			assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
		})

	})

	t.Run("nok - error while drawing up contract", func(t *testing.T) {
		ctx := createContext(t)

		params := DrawUpContractRequest{
			Language:    "EN",
			Type:        "PractitionerLogin",
			Version:     "v3",
			LegalEntity: vdr.TestDIDA.String(),
		}
		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), nil).Return(nil, errors.New("unknown error while drawing up the contract"))

		response, err := ctx.wrapper.DrawUpContract(ctx.audit, DrawUpContractRequestObject{Body: &params})

		assert.Nil(t, response)
		assert.EqualError(t, err, "unknown error while drawing up the contract")
	})
}

func TestWrapper_CreateJwtGrant(t *testing.T) {
	t.Run("make request", func(t *testing.T) {
		ctx := createContext(t)
		body := CreateJwtGrantRequest{
			Requester:  vdr.TestDIDA.String(),
			Authorizer: vdr.TestDIDB.String(),
			Identity: &vc.VerifiablePresentation{
				Type: []ssi.URI{ssi.MustParseURI("test'")},
			},
			Service: "service",
		}
		expectedResponse := CreateJwtGrant200JSONResponse{
			BearerToken:                 "123.456.789",
			AuthorizationServerEndpoint: "http://oauth",
		}

		expectedRequest := services.CreateJwtGrantRequest{
			Requester:  body.Requester,
			Authorizer: body.Authorizer,
			IdentityVP: body.Identity,
			Service:    "service",
		}

		ctx.relyingPartyMock.EXPECT().CreateJwtGrant(gomock.Any(), expectedRequest).Return(&services.JwtBearerTokenResult{
			BearerToken:                 expectedResponse.BearerToken,
			AuthorizationServerEndpoint: expectedResponse.AuthorizationServerEndpoint,
		}, nil)

		response, err := ctx.wrapper.CreateJwtGrant(ctx.audit, CreateJwtGrantRequestObject{Body: &body})

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})
}

func TestWrapper_RequestAccessToken(t *testing.T) {
	testID := vc.VerifiablePresentation{
		Type: []ssi.URI{ssi.MustParseURI("test'")},
	}
	fakeRequest := RequestAccessTokenRequest{
		Requester:  vdr.TestDIDA.String(),
		Authorizer: vdr.TestDIDB.String(),
		Identity:   &testID,
		Service:    "test-service",
	}

	t.Run("returns error when creating jwt grant fails", func(t *testing.T) {
		ctx := createContext(t)

		ctx.relyingPartyMock.EXPECT().
			CreateJwtGrant(gomock.Any(), services.CreateJwtGrantRequest{
				Requester:  vdr.TestDIDA.String(),
				Authorizer: vdr.TestDIDB.String(),
				IdentityVP: &testID,
				Service:    "test-service",
			}).
			Return(nil, errors.New("random error"))

		response, err := ctx.wrapper.RequestAccessToken(ctx.audit, RequestAccessTokenRequestObject{Body: &fakeRequest})

		assert.Nil(t, response)
		assert.EqualError(t, err, "random error")
	})

	const bearerToken = "jwt-bearer-token"
	var authEndpointURL, _ = url.Parse("https://auth-server")
	t.Run("returns error when access token request fails", func(t *testing.T) {
		ctx := createContext(t)

		ctx.relyingPartyMock.EXPECT().
			CreateJwtGrant(ctx.audit, services.CreateJwtGrantRequest{
				Requester:  vdr.TestDIDA.String(),
				Authorizer: vdr.TestDIDB.String(),
				IdentityVP: &testID,
				Service:    "test-service",
			}).
			Return(&services.JwtBearerTokenResult{
				BearerToken:                 bearerToken,
				AuthorizationServerEndpoint: authEndpointURL.String(),
			}, nil)
		ctx.relyingPartyMock.EXPECT().RequestAccessToken(gomock.Any(), bearerToken, *authEndpointURL).Return(nil, errors.New("random error"))

		response, err := ctx.wrapper.RequestAccessToken(ctx.audit, RequestAccessTokenRequestObject{Body: &fakeRequest})

		assert.Nil(t, response)
		assert.EqualError(t, err, "random error")
		require.Implements(t, new(core.HTTPStatusCodeError), err)
		assert.Equal(t, http.StatusServiceUnavailable, err.(core.HTTPStatusCodeError).StatusCode())
	})

	t.Run("happy_path", func(t *testing.T) {
		ctx := createContext(t)

		credentials := []vc.VerifiableCredential{
			{
				Context:      []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
				ID:           &ssi.URI{},
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
			},
		}

		request := fakeRequest
		request.Credentials = credentials

		expectedResponse := AccessTokenResponse{
			TokenType:   "token-type",
			ExpiresIn:   10,
			AccessToken: "actual-token",
		}

		ctx.relyingPartyMock.EXPECT().
			CreateJwtGrant(ctx.audit, services.CreateJwtGrantRequest{
				Requester:   vdr.TestDIDA.String(),
				Authorizer:  vdr.TestDIDB.String(),
				IdentityVP:  &testID,
				Service:     "test-service",
				Credentials: credentials,
			}).
			Return(&services.JwtBearerTokenResult{
				BearerToken:                 bearerToken,
				AuthorizationServerEndpoint: authEndpointURL.String(),
			}, nil)
		ctx.relyingPartyMock.EXPECT().
			RequestAccessToken(gomock.Any(), bearerToken, *authEndpointURL).
			Return(&expectedResponse, nil)

		response, err := ctx.wrapper.RequestAccessToken(ctx.audit, RequestAccessTokenRequestObject{Body: &request})

		assert.Equal(t, RequestAccessToken200JSONResponse(expectedResponse), response)
		assert.NoError(t, err)
	})
}

func TestWrapper_CreateAccessToken(t *testing.T) {
	const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6NDgwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjoxNTc4MTEwNDgxLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.76XtU81IyR3Ak_2fgrYsuLcvxndf0eedT1mFPa-rPXk"

	t.Run("unknown grant_type", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "unknown type"}

		errorDescription := "grant_type must be: 'urn:ietf:params:oauth:grant-type:jwt-bearer'"
		expectedResponse := CreateAccessToken400JSONResponse{ErrorDescription: errorDescription, Error: errOauthUnsupportedGrant}

		response, err := ctx.wrapper.CreateAccessToken(ctx.audit, CreateAccessTokenRequestObject{Body: &params})

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})

	t.Run("invalid assertion", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: "invalid jwt"}

		errorDescription := "Assertion must be a valid encoded jwt"
		expectedResponse := CreateAccessToken400JSONResponse{ErrorDescription: errorDescription, Error: errOauthInvalidGrant}

		response, err := ctx.wrapper.CreateAccessToken(ctx.audit, CreateAccessTokenRequestObject{Body: &params})

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})

	t.Run("auth.CreateAccessToken returns error", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}

		errorDescription := "oh boy"
		expectedResponse := CreateAccessToken400JSONResponse{ErrorDescription: errorDescription, Error: errOauthInvalidRequest}

		ctx.authzServerMock.EXPECT().CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(nil, &oauth.ErrorResponse{
			Description: errors.New(errorDescription),
			Code:        errOauthInvalidRequest,
		})

		response, err := ctx.wrapper.CreateAccessToken(ctx.audit, CreateAccessTokenRequestObject{Body: &params})

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}

		pkgResponse := &services.AccessTokenResult{AccessToken: "foo", ExpiresIn: 800000}
		ctx.authzServerMock.EXPECT().CreateAccessToken(gomock.Any(), services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(pkgResponse, nil)

		expectedResponse := CreateAccessToken200JSONResponse{
			AccessToken: pkgResponse.AccessToken,
			ExpiresIn:   800000,
			TokenType:   "bearer",
		}

		response, err := ctx.wrapper.CreateAccessToken(ctx.audit, CreateAccessTokenRequestObject{Body: &params})

		assert.Equal(t, expectedResponse, response)
		assert.Nil(t, err)
	})
}

func TestWrapper_VerifyAccessToken(t *testing.T) {
	t.Run("403 - missing header", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "",
		}

		response, err := ctx.wrapper.VerifyAccessToken(ctx.audit, VerifyAccessTokenRequestObject{params})

		assert.Equal(t, VerifyAccessToken403Response{}, response)
		assert.NoError(t, err)
	})

	t.Run("403 - incorrect authorization header", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "34987569ytihua",
		}

		response, err := ctx.wrapper.VerifyAccessToken(ctx.audit, VerifyAccessTokenRequestObject{params})

		assert.Equal(t, VerifyAccessToken403Response{}, response)
		assert.NoError(t, err)
	})

	t.Run("403 - incorrect token", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}
		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, "token").Return(nil, errors.New("unauthorized"))

		response, err := ctx.wrapper.VerifyAccessToken(ctx.audit, VerifyAccessTokenRequestObject{params})

		assert.Equal(t, VerifyAccessToken403Response{}, response)
		assert.NoError(t, err)
	})

	t.Run("200 - correct token", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}
		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, "token").Return(&services.NutsAccessToken{}, nil)

		response, err := ctx.wrapper.VerifyAccessToken(ctx.audit, VerifyAccessTokenRequestObject{params})

		assert.Equal(t, VerifyAccessToken200Response{}, response)
		assert.NoError(t, err)
	})
}

func TestWrapper_IntrospectAccessToken(t *testing.T) {
	t.Run("empty token returns active false", func(t *testing.T) {
		ctx := createContext(t)

		request := IntrospectAccessTokenFormdataRequestBody{Token: ""}

		expectedResponse := IntrospectAccessToken200JSONResponse{Active: false}

		response, err := ctx.wrapper.IntrospectAccessToken(ctx.audit, IntrospectAccessTokenRequestObject{Body: &request})

		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})

	aud := "123"
	aid := vdr.TestDIDA.String()
	exp := 1581412667
	iat := 1581411767
	iss := vdr.TestDIDB.String()
	service := "service"

	t.Run("introspect a token", func(t *testing.T) {
		ctx := createContext(t)

		request := IntrospectAccessTokenFormdataRequestBody{Token: "123"}

		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, request.Token).Return(
			&services.NutsAccessToken{
				Audience:    aud,
				Expiration:  int64(exp),
				IssuedAt:    int64(iat),
				Issuer:      iss,
				Subject:     aid,
				Service:     service,
				Credentials: []string{"credentialID-1", "credentialID-2"},
			}, nil)
		ctx.cedentialResolverMock.EXPECT().Resolve(ssi.MustParseURI("credentialID-1"), nil).Return(nil, errors.New("not found"))
		ctx.cedentialResolverMock.EXPECT().Resolve(ssi.MustParseURI("credentialID-2"), nil).Return(&vc.VerifiableCredential{}, nil)

		credentials := []string{"credentialID-1", "credentialID-2"}

		resolvedVCs := []VerifiableCredential{{}}
		expectedResponse := IntrospectAccessToken200JSONResponse{
			Active: true,
			Aud:    &aud,
			Exp:    &exp,
			Iat:    &iat,
			Iss:    &iss,
			Sub:    &aid,
			//Uid:    &uid,
			Service:     &service,
			Vcs:         &credentials,
			ResolvedVCs: &resolvedVCs,
		}

		response, err := ctx.wrapper.IntrospectAccessToken(ctx.audit, IntrospectAccessTokenRequestObject{Body: &request})

		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})
	t.Run("with all fields", func(t *testing.T) {
		ctx := createContext(t)

		request := IntrospectAccessTokenFormdataRequestBody{Token: "123"}

		initials := "I"
		prefix := "Mr."
		familyName := "Family"
		email := "email"
		assuranceLevel := "low"
		username := "admin"
		userRole := "root"
		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, request.Token).Return(
			&services.NutsAccessToken{
				Service:        service,
				Initials:       &initials,
				Prefix:         &prefix,
				FamilyName:     &familyName,
				Email:          &email,
				AssuranceLevel: &assuranceLevel,
				Username:       &username,
				UserRole:       &userRole,
				Expiration:     int64(exp),
				IssuedAt:       int64(iat),
				Issuer:         iss,
				Subject:        aid,
				Audience:       aud,
				Credentials:    []string{"credentialID-1", "credentialID-2"},
			}, nil)
		ctx.cedentialResolverMock.EXPECT().Resolve(ssi.MustParseURI("credentialID-1"), nil).Return(nil, errors.New("not found"))
		ctx.cedentialResolverMock.EXPECT().Resolve(ssi.MustParseURI("credentialID-2"), nil).Return(&vc.VerifiableCredential{}, nil)

		credentials := []string{"credentialID-1", "credentialID-2"}

		resolvedVCs := []VerifiableCredential{{}}
		al := Low
		expectedResponse := IntrospectAccessToken200JSONResponse{
			Active: true,
			Aud:    &aud,
			Exp:    &exp,
			Iat:    &iat,
			Iss:    &iss,
			Sub:    &aid,
			//Uid:    &uid,
			Service:        &service,
			Vcs:            &credentials,
			ResolvedVCs:    &resolvedVCs,
			Initials:       &initials,
			Prefix:         &prefix,
			FamilyName:     &familyName,
			Email:          &email,
			AssuranceLevel: &al,
			Username:       &username,
			UserRole:       &userRole,
		}

		response, err := ctx.wrapper.IntrospectAccessToken(ctx.audit, IntrospectAccessTokenRequestObject{Body: &request})

		assert.Equal(t, expectedResponse, response)
		assert.NoError(t, err)
	})
}

type signSessionResponseMatcher struct {
	means string
}

func (s signSessionResponseMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	return string(x.(SignSessionResponse).Means) == s.means && x.(SignSessionResponse).SessionPtr["sessionID"] != ""
}

func (s signSessionResponseMatcher) String() string {
	return fmt.Sprintf("{%v somePtr}", s.means)
}

func TestWrapper_CreateSignSession(t *testing.T) {
	t.Run("create a dummy signing session", func(t *testing.T) {
		ctx := createContext(t)

		dummyMeans := dummy.Dummy{
			InStrictMode: false,
			Sessions:     map[string]string{},
			Status:       map[string]string{},
		}

		ctx.contractClientMock.EXPECT().CreateSigningSession(gomock.Any()).DoAndReturn(
			func(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
				return dummyMeans.StartSigningSession(contract.Contract{RawContractText: sessionRequest.Message}, nil)
			})

		postParams := SignSessionRequest{
			Means:   "dummy",
			Payload: "this is the contract message to agree to",
		}

		response, err := ctx.wrapper.CreateSignSession(ctx.audit, CreateSignSessionRequestObject{Body: &postParams})

		assert.IsType(t, CreateSignSession201JSONResponse{}, response)
		//TODO: check repsonse.SessionPtr["sessionID"] != ""
		assert.NoError(t, err)
	})

	t.Run("nok - error while creating signing session", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignSessionRequest{}

		ctx.contractClientMock.EXPECT().CreateSigningSession(gomock.Any()).Return(nil, errors.New("some error"))

		response, err := ctx.wrapper.CreateSignSession(ctx.audit, CreateSignSessionRequestObject{Body: &postParams})

		assert.Nil(t, response)
		assert.EqualError(t, err, "unable to create sign challenge: some error")
	})
}

func TestWrapper_VerifySignature(t *testing.T) {
	t.Run("ok - VP without checkTime", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{
				Context: []ssi.URI{ssi.MustParseURI("http://example.com")},
				Proof:   []interface{}{vc.JSONWebSignature2020Proof{Jws: "token"}},
				Type:    []ssi.URI{ssi.MustParseURI("TestCredential")},
			}}

		verificationResult := services.TestVPVerificationResult{
			Val:         contract.Valid,
			Type:        "AVPType",
			DAttributes: map[string]string{"name": "John"},
			CAttributes: map[string]string{"validTo": "now"},
		}

		vpType := "AVPType"
		issuerAttributes := map[string]interface{}{"name": "John"}
		credentials := map[string]interface{}{"validTo": "now"}

		expectedResponse := SignatureVerificationResponse{
			Credentials:      &credentials,
			IssuerAttributes: &issuerAttributes,
			Validity:         true,
			VpType:           &vpType,
		}

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(verificationResult, nil)

		response, err := ctx.wrapper.VerifySignature(ctx.audit, VerifySignatureRequestObject{Body: &postParams})

		assert.Equal(t, VerifySignature200JSONResponse(expectedResponse), response)
		assert.NoError(t, err)
	})

	t.Run("ok - but invalid VP", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{}}

		verificationResult := services.TestVPVerificationResult{
			Val: contract.Invalid,
		}

		expectedResponse := SignatureVerificationResponse{
			Validity: false,
		}

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(verificationResult, nil)

		response, err := ctx.wrapper.VerifySignature(ctx.audit, VerifySignatureRequestObject{Body: &postParams})

		assert.Equal(t, VerifySignature200JSONResponse(expectedResponse), response)
		assert.NoError(t, err)
	})

	t.Run("ok - valid checkTime", func(t *testing.T) {
		ctx := createContext(t)

		checkTimeParam := "2021-01-15T09:59:00+01:00"
		postParams := SignatureVerificationRequest{
			CheckTime: &checkTimeParam,
			VerifiablePresentation: VerifiablePresentation{
				Context: []ssi.URI{ssi.MustParseURI("http://example.com")},
				Proof:   []interface{}{vc.JSONWebSignature2020Proof{Jws: "token"}},
				Type:    []ssi.URI{ssi.MustParseURI("TestCredential")},
			}}

		verificationResult := services.TestVPVerificationResult{
			Val: contract.Valid,
		}

		vpType := ""
		issuerAttributes := map[string]interface{}{}
		credentials := map[string]interface{}{}

		expectedResponse := SignatureVerificationResponse{
			Credentials:      &credentials,
			IssuerAttributes: &issuerAttributes,
			Validity:         true,
			VpType:           &vpType,
		}

		checkTime, err := time.Parse(time.RFC3339, checkTimeParam)
		require.NoError(t, err)

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), &checkTime).Return(verificationResult, nil)

		response, err := ctx.wrapper.VerifySignature(ctx.audit, VerifySignatureRequestObject{Body: &postParams})

		assert.Equal(t, VerifySignature200JSONResponse(expectedResponse), response)
		assert.NoError(t, err)
	})

	t.Run("nok - invalid checkTime", func(t *testing.T) {
		ctx := createContext(t)

		invalidCheckTime := "invalid formatted timestamp"
		postParams := SignatureVerificationRequest{
			CheckTime:              &invalidCheckTime,
			VerifiablePresentation: VerifiablePresentation{},
		}

		response, err := ctx.wrapper.VerifySignature(ctx.audit, VerifySignatureRequestObject{Body: &postParams})

		assert.Nil(t, response)
		assert.EqualError(t, err, "could not parse checkTime: parsing time \"invalid formatted timestamp\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"invalid formatted timestamp\" as \"2006\"")
	})

	t.Run("nok - verification returns an error", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{},
		}

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(nil, errors.New("verification error"))

		response, err := ctx.wrapper.VerifySignature(ctx.audit, VerifySignatureRequestObject{Body: &postParams})

		assert.Nil(t, response)
		assert.EqualError(t, err, "unable to verify the verifiable presentation: verification error")
	})
}
