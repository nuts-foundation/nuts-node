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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/go-did/did"
	pkg2 "github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr"
)

type TestContext struct {
	ctrl                  *gomock.Controller
	echoMock              *mock.MockContext
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

func (m *mockAuthClient) AuthzServer() oauth.AuthorizationServer {
	return m.authzServer
}

func (m *mockAuthClient) RelyingParty() oauth.RelyingParty {
	return m.relyingParty
}

func (m *mockAuthClient) ContractNotary() services.ContractNotary {
	return m.contractNotary
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
	echoMock := mock.NewMockContext(ctrl)
	request, _ := http.NewRequestWithContext(requestCtx, "GET", "/", nil)
	echoMock.EXPECT().Request().Return(request).AnyTimes()

	return &TestContext{
		ctrl:                  ctrl,
		echoMock:              echoMock,
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

func TestWrapper_Preprocess(t *testing.T) {
	w := &Wrapper{}
	echoCtx := echo.New().NewContext(&http.Request{}, nil)
	echoCtx.Set(core.UserContextKey, "user")

	w.Preprocess("foo", echoCtx)

	audit.AssertAuditInfo(t, echoCtx, "user@", "Auth", "foo")
	assert.Equal(t, "foo", echoCtx.Get(core.OperationIDContextKey))
	assert.Equal(t, "Auth", echoCtx.Get(core.ModuleNameContextKey))
	assert.Same(t, w, echoCtx.Get(core.StatusCodeResolverContextKey))
}

func TestWrapper_GetSignSessionStatus(t *testing.T) {
	t.Run("ok - started without VP", func(t *testing.T) {
		ctx := createContext(t)

		signingSessionID := "123"
		signingSessionStatus := "started"

		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		var vp interface{}
		signingSessionResult.EXPECT().VerifiablePresentation().Return(vp, nil)

		signingSessionResult.EXPECT().Status().Return(signingSessionStatus)

		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(signingSessionResult, nil)

		response := SignSessionStatusResponse{
			Status:                 signingSessionStatus,
			VerifiablePresentation: nil,
		}

		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.NoError(t, err)
	})

	t.Run("ok - completed with VP", func(t *testing.T) {
		ctx := createContext(t)
		signingSessionID := "123"
		signingSessionStatus := "completed"
		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)
		vp := vc.VerifiablePresentation{
			Context: []ssi.URI{vc.VCContextV1URI()},
		}
		signingSessionResult.EXPECT().VerifiablePresentation().Return(&vp, nil)
		signingSessionResult.EXPECT().Status().Return(signingSessionStatus)
		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(signingSessionResult, nil)
		response := SignSessionStatusResponse{
			Status: signingSessionStatus,
			VerifiablePresentation: &vc.VerifiablePresentation{
				Context: []ssi.URI{vc.VCContextV1URI()},
			},
		}

		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.NoError(t, err)
	})

	t.Run("nok - SigningSessionStatus returns error", func(t *testing.T) {
		ctx := createContext(t)

		signingSessionID := "123"
		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(nil, services.ErrSessionNotFound)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)

		assert.ErrorIs(t, err, services.ErrSessionNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("nok - unable to build a VP", func(t *testing.T) {
		ctx := createContext(t)

		signingSessionID := "123"
		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		signingSessionResult.EXPECT().VerifiablePresentation().Return(nil, errors.New("missing key"))

		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(signingSessionResult, nil)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)

		assert.EqualError(t, err, "error while building verifiable presentation: missing key")
	})
}

func TestWrapper_GetContractByType(t *testing.T) {
	t.Run("get known contact", func(t *testing.T) {
		ctx := createContext(t)

		cType := "PractitionerLogin"
		cVersion := "v3"
		cLanguage := "EN"
		params := GetContractByTypeParams{
			Version:  &cVersion,
			Language: &cLanguage,
		}

		a := contract.StandardContractTemplates.Get(contract.Type(cType), contract.Language(cLanguage), contract.Version(cVersion))
		answer := Contract{
			Language:           ContractLanguage(a.Language),
			Template:           &a.Template,
			TemplateAttributes: &a.TemplateAttributes,
			Type:               ContractType(a.Type),
			Version:            ContractVersion(a.Version),
		}

		ctx.echoMock.EXPECT().JSON(http.StatusOK, answer)

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.GetContractByType(ctx.echoMock, cType, params)

		assert.Nil(t, err)
	})

	t.Run("get an unknown contract", func(t *testing.T) {
		ctx := createContext(t)

		cType := "UnknownContract"
		params := GetContractByTypeParams{}

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.GetContractByType(ctx.echoMock, cType, params)

		assert.ErrorIs(t, err, core.NotFoundError(""))
	})
}

func TestWrapper_DrawUpContract(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body DrawUpContractRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	t.Run("ok - it can draw up a standard contract", func(t *testing.T) {
		ctx := createContext(t)

		params := DrawUpContractRequest{
			Language:    "EN",
			Type:        "PractitionerLogin",
			Version:     "v3",
			LegalEntity: vdr.TestDIDA.String(),
		}
		bindPostBody(ctx, params)

		template := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v3"]
		drawnUpContract := &contract.Contract{
			RawContractText: "drawn up contract text",
			Template:        template,
			Params:          nil,
		}
		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, *template, gomock.Any(), gomock.Any(), gomock.Any(), nil).Return(drawnUpContract, nil)

		expectedResponse := ContractResponse{
			Language: "EN",
			Message:  "drawn up contract text",
			Type:     "PractitionerLogin",
			Version:  "v3",
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)
		err := ctx.wrapper.DrawUpContract(ctx.echoMock)
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
		bindPostBody(ctx, params)

		template := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v3"]
		drawnUpContract := &contract.Contract{
			RawContractText: "drawn up contract text",
			Template:        template,
			Params:          nil,
		}
		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, *template, gomock.Any(), gomock.Any(), gomock.Any(), &vc).Return(drawnUpContract, nil)

		expectedResponse := ContractResponse{
			Language: "EN",
			Message:  "drawn up contract text",
			Type:     "PractitionerLogin",
			Version:  "v3",
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)
		err := ctx.wrapper.DrawUpContract(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - wrong parameters", func(t *testing.T) {
		t.Run("invalid formatted validFrom", func(t *testing.T) {
			ctx := createContext(t)

			validFrom := "02 Jan 2010"

			params := DrawUpContractRequest{
				ValidFrom: &validFrom,
			}
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

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
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

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
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

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
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

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
		bindPostBody(ctx, params)

		ctx.notaryMock.EXPECT().DrawUpContract(ctx.audit, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), nil).Return(nil, errors.New("unknown error while drawing up the contract"))

		err := ctx.wrapper.DrawUpContract(ctx.echoMock)

		assert.EqualError(t, err, "unknown error while drawing up the contract")
	})
}

func TestWrapper_CreateJwtGrant(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateJwtGrantRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	expectStatusOK := func(ctx *TestContext, response JwtGrantResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)
	}

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
		bindPostBody(ctx, body)
		response := JwtGrantResponse{
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
			BearerToken:                 response.BearerToken,
			AuthorizationServerEndpoint: response.AuthorizationServerEndpoint,
		}, nil)
		expectStatusOK(ctx, response)

		assert.Nil(t, ctx.wrapper.CreateJwtGrant(ctx.echoMock))
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

	t.Run("returns error when request is invalid", func(t *testing.T) {
		ctx := createContext(t)

		ctx.echoMock.EXPECT().
			Bind(gomock.Any()).
			Return(errors.New("random error"))

		err := ctx.wrapper.RequestAccessToken(ctx.echoMock)

		assert.EqualError(t, err, "random error")
	})

	t.Run("returns error when creating jwt grant fails", func(t *testing.T) {
		ctx := createContext(t)

		ctx.echoMock.EXPECT().
			Bind(gomock.Any()).
			DoAndReturn(func(input interface{}) error {
				*input.(*RequestAccessTokenRequest) = fakeRequest
				return nil
			})

		ctx.relyingPartyMock.EXPECT().
			CreateJwtGrant(gomock.Any(), services.CreateJwtGrantRequest{
				Requester:  vdr.TestDIDA.String(),
				Authorizer: vdr.TestDIDB.String(),
				IdentityVP: &testID,
				Service:    "test-service",
			}).
			Return(nil, errors.New("random error"))

		err := ctx.wrapper.RequestAccessToken(ctx.echoMock)

		assert.EqualError(t, err, "random error")
	})

	const bearerToken = "jwt-bearer-token"
	var authEndpointURL, _ = url.Parse("https://auth-server")
	t.Run("returns error when access token request fails", func(t *testing.T) {
		ctx := createContext(t)

		ctx.echoMock.EXPECT().
			Bind(gomock.Any()).
			DoAndReturn(func(input interface{}) error {
				*input.(*RequestAccessTokenRequest) = fakeRequest
				return nil
			})

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

		err := ctx.wrapper.RequestAccessToken(ctx.echoMock)

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

		ctx.echoMock.EXPECT().
			Bind(gomock.Any()).
			DoAndReturn(func(input interface{}) error {
				request := fakeRequest
				request.Credentials = credentials

				*input.(*RequestAccessTokenRequest) = request
				return nil
			})

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
			Return(&AccessTokenResponse{
				TokenType:   "token-type",
				ExpiresIn:   10,
				AccessToken: "actual-token",
			}, nil)

		ctx.echoMock.EXPECT().
			JSON(http.StatusOK, &AccessTokenResponse{
				TokenType:   "token-type",
				ExpiresIn:   10,
				AccessToken: "actual-token",
			}).
			Return(nil)

		err := ctx.wrapper.RequestAccessToken(ctx.echoMock)

		assert.NoError(t, err)
	})
}

func TestWrapper_CreateAccessToken(t *testing.T) {
	const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6NDgwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjoxNTc4MTEwNDgxLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.76XtU81IyR3Ak_2fgrYsuLcvxndf0eedT1mFPa-rPXk"

	bindPostBody := func(ctx *TestContext, body CreateAccessTokenRequest) {
		ctx.echoMock.EXPECT().FormValue("assertion").Return(body.Assertion)
		ctx.echoMock.EXPECT().FormValue("grant_type").Return(body.GrantType)
	}

	expectError := func(ctx *TestContext, err AccessTokenRequestFailedResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusBadRequest, oauthErrorMatcher{x: err})
	}

	expectStatusOK := func(ctx *TestContext, response AccessTokenResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.Eq(response))
	}

	t.Run("unknown grant_type", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "unknown type"}
		bindPostBody(ctx, params)

		errorDescription := "grant_type must be: 'urn:ietf:params:oauth:grant-type:jwt-bearer'"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errOauthUnsupportedGrant}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("invalid assertion", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: "invalid jwt"}
		bindPostBody(ctx, params)

		errorDescription := "Assertion must be a valid encoded jwt"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errOauthInvalidGrant}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("auth.CreateAccessToken returns error", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		errorDescription := "oh boy"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errOauthInvalidRequest}
		expectError(ctx, errorResponse)

		ctx.authzServerMock.EXPECT().CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(nil, &oauth.ErrorResponse{
			Description: errors.New(errorDescription),
			Code:        errOauthInvalidRequest,
		})
		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		pkgResponse := &services.AccessTokenResult{AccessToken: "foo", ExpiresIn: 800000}
		ctx.authzServerMock.EXPECT().CreateAccessToken(gomock.Any(), services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(pkgResponse, nil)

		apiResponse := AccessTokenResponse{
			AccessToken: pkgResponse.AccessToken,
			ExpiresIn:   800000,
			TokenType:   "bearer",
		}
		expectStatusOK(ctx, apiResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})
}

func TestWrapper_VerifyAccessToken(t *testing.T) {
	t.Run("403 - missing header", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("403 - incorrect authorization header", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "34987569ytihua",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("403 - incorrect token", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)
		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, "token").Return(nil, errors.New("unauthorized"))

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("200 - correct token", func(t *testing.T) {
		ctx := createContext(t)
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusOK)
		ctx.authzServerMock.EXPECT().IntrospectAccessToken(ctx.audit, "token").Return(&services.NutsAccessToken{}, nil)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})
}

func TestWrapper_IntrospectAccessToken(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body TokenIntrospectionRequest) {
		ctx.echoMock.EXPECT().FormValue("token").Return(body.Token)
	}

	expectStatusOK := func(ctx *TestContext, response TokenIntrospectionResponse) {
		data, _ := json.Marshal(response)
		logrus.Infof("Expect: %s", string(data))
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.Eq(response))
	}

	t.Run("empty token returns active false", func(t *testing.T) {
		ctx := createContext(t)

		request := TokenIntrospectionRequest{Token: ""}
		bindPostBody(ctx, request)

		response := TokenIntrospectionResponse{Active: false}
		expectStatusOK(ctx, response)

		_ = ctx.wrapper.IntrospectAccessToken(ctx.echoMock)
	})

	t.Run("introspect a token", func(t *testing.T) {
		ctx := createContext(t)

		request := TokenIntrospectionRequest{Token: "123"}
		bindPostBody(ctx, request)

		aud := "123"
		aid := vdr.TestDIDA.String()
		exp := 1581412667
		iat := 1581411767
		iss := vdr.TestDIDB.String()
		service := "service"
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
		response := TokenIntrospectionResponse{
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

		expectStatusOK(ctx, response)

		err := ctx.wrapper.IntrospectAccessToken(ctx.echoMock)

		assert.NoError(t, err)
	})
}

type oauthErrorMatcher struct {
	x AccessTokenRequestFailedResponse
}

func (e oauthErrorMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	response := x.(AccessTokenRequestFailedResponse)
	return e.x.Error == response.Error && e.x.ErrorDescription == response.ErrorDescription
}

func (e oauthErrorMatcher) String() string {
	return fmt.Sprintf("is equal to {%v, %v}", e.x.Error, e.x.ErrorDescription)
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
	bindPostBody := func(ctx *TestContext, body SignSessionRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	t.Run("create a dummy signing session", func(t *testing.T) {
		ctx := createContext(t)

		dummyMeans := dummy.Dummy{
			InStrictMode: false,
			Sessions:     map[string]string{},
			Status:       map[string]string{},
		}

		ctx.contractClientMock.EXPECT().CreateSigningSession(gomock.Any()).DoAndReturn(
			func(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
				return dummyMeans.StartSigningSession(sessionRequest.Message)
			})

		postParams := SignSessionRequest{
			Means:   "dummy",
			Payload: "this is the contract message to agree to",
		}
		bindPostBody(ctx, postParams)

		ctx.echoMock.EXPECT().JSON(http.StatusCreated, signSessionResponseMatcher{means: "dummy"})
		err := ctx.wrapper.CreateSignSession(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - error while creating signing session", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignSessionRequest{}
		bindPostBody(ctx, postParams)

		ctx.contractClientMock.EXPECT().CreateSigningSession(gomock.Any()).Return(nil, errors.New("some error"))

		err := ctx.wrapper.CreateSignSession(ctx.echoMock)

		assert.EqualError(t, err, "unable to create sign challenge: some error")
	})
}

func TestWrapper_VerifySignature(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body SignatureVerificationRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	t.Run("ok - VP without checkTime", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{
				Context: []ssi.URI{ssi.MustParseURI("http://example.com")},
				Proof:   []interface{}{vc.JSONWebSignature2020Proof{Jws: "token"}},
				Type:    []ssi.URI{ssi.MustParseURI("TestCredential")},
			}}

		bindPostBody(ctx, postParams)

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
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)

		err := ctx.wrapper.VerifySignature(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("ok - but invalid VP", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{}}

		bindPostBody(ctx, postParams)

		verificationResult := services.TestVPVerificationResult{
			Val: contract.Invalid,
		}

		expectedResponse := SignatureVerificationResponse{
			Validity: false,
		}

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(verificationResult, nil)
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)

		err := ctx.wrapper.VerifySignature(ctx.echoMock)
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

		bindPostBody(ctx, postParams)

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
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)

		err = ctx.wrapper.VerifySignature(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - invalid checkTime", func(t *testing.T) {
		ctx := createContext(t)

		invalidCheckTime := "invalid formatted timestamp"
		postParams := SignatureVerificationRequest{
			CheckTime:              &invalidCheckTime,
			VerifiablePresentation: VerifiablePresentation{},
		}

		bindPostBody(ctx, postParams)

		err := ctx.wrapper.VerifySignature(ctx.echoMock)

		assert.EqualError(t, err, "could not parse checkTime: parsing time \"invalid formatted timestamp\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"invalid formatted timestamp\" as \"2006\"")
	})

	t.Run("nok - verification returns an error", func(t *testing.T) {
		ctx := createContext(t)

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{},
		}

		bindPostBody(ctx, postParams)

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(nil, errors.New("verification error"))

		err := ctx.wrapper.VerifySignature(ctx.echoMock)

		assert.EqualError(t, err, "unable to verify the verifiable presentation: verification error")
	})
}
