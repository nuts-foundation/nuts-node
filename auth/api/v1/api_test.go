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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/sirupsen/logrus"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	pkg2 "github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
)

type TestContext struct {
	ctrl               *gomock.Controller
	echoMock           *mock.MockContext
	authMock           pkg2.AuthenticationServices
	notaryMock         *services.MockContractNotary
	contractClientMock *services.MockContractClient
	oauthClientMock    *services.MockOAuthClient
	wrapper            Wrapper
}

type mockAuthClient struct {
	ctrl               *gomock.Controller
	mockContractClient *services.MockContractClient
	mockContractNotary *services.MockContractNotary
	mockOAuthClient    *services.MockOAuthClient
}

func (m *mockAuthClient) OAuthClient() services.OAuthClient {
	return m.mockOAuthClient
}

func (m *mockAuthClient) ContractClient() services.ContractClient {
	return m.mockContractClient
}

func (m *mockAuthClient) ContractNotary() services.ContractNotary {
	return m.mockContractNotary
}

func createContext(t *testing.T) *TestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockContractClient := services.NewMockContractClient(ctrl)
	mockContractNotary := services.NewMockContractNotary(ctrl)
	mockOAuthClient := services.NewMockOAuthClient(ctrl)
	authMock := &mockAuthClient{ctrl: ctrl, mockContractClient: mockContractClient, mockContractNotary: mockContractNotary, mockOAuthClient: mockOAuthClient}
	return &TestContext{
		ctrl:               ctrl,
		echoMock:           mock.NewMockContext(ctrl),
		authMock:           authMock,
		notaryMock:         mockContractNotary,
		contractClientMock: mockContractClient,
		oauthClientMock:    mockOAuthClient,
		wrapper:            Wrapper{Auth: authMock},
	}
}

func TestWrapper_GetSignSessionStatus(t *testing.T) {
	t.Run("ok - started without VP", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		signingSessionID := "123"
		signingSessionStatus := "completed"

		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		vp := struct {
			Context []string `json:"@context"`
		}{Context: []string{"http://example.com"}}
		signingSessionResult.EXPECT().VerifiablePresentation().Return(vp, nil)

		signingSessionResult.EXPECT().Status().Return(signingSessionStatus)

		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(signingSessionResult, nil)

		response := SignSessionStatusResponse{
			Status:                 signingSessionStatus,
			VerifiablePresentation: &VerifiablePresentation{Context: []string{"http://example.com"}},
		}

		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.NoError(t, err)
	})

	t.Run("nok - SigningSessionStatus returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		signingSessionID := "123"
		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(nil, services.ErrSessionNotFound)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)

		assert.ErrorIs(t, err, services.ErrSessionNotFound)
	})

	t.Run("nok - unable to build a VP", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		cType := "UnknownContract"
		params := GetContractByTypeParams{}

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.GetContractByType(ctx.echoMock, cType, params)

		assert.EqualError(t, err, "could not find contract template")
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
		defer ctx.ctrl.Finish()

		params := DrawUpContractRequest{
			Language:    ContractLanguage("EN"),
			Type:        ContractType("PractitionerLogin"),
			Version:     ContractVersion("v3"),
			LegalEntity: LegalEntity(vdr.TestDIDA.String()),
		}
		bindPostBody(ctx, params)

		template := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v3"]
		drawnUpContract := &contract.Contract{
			RawContractText: "drawn up contract text",
			Template:        template,
			Params:          nil,
		}
		ctx.notaryMock.EXPECT().DrawUpContract(*template, gomock.Any(), gomock.Any(), gomock.Any()).Return(drawnUpContract, nil)

		expectedResponse := ContractResponse{
			Language: ContractLanguage("EN"),
			Message:  "drawn up contract text",
			Type:     ContractType("PractitionerLogin"),
			Version:  ContractVersion("v3"),
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)
		err := ctx.wrapper.DrawUpContract(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - wrong parameters", func(t *testing.T) {
		t.Run("invalid formatted validFrom", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			validFrom := "02 Jan 2010"

			params := DrawUpContractRequest{
				ValidFrom: &validFrom,
			}
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.EqualError(t, err, "could not parse validFrom: parsing time \"02 Jan 2010\" as \"2006-01-02T15:04:05-07:00\": cannot parse \"an 2010\" as \"2006\"")
		})

		t.Run("invalid formatted duration", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			duration := "15 minutes"

			params := DrawUpContractRequest{
				ValidDuration: &duration,
			}
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.EqualError(t, err, "could not parse validDuration: time: unknown unit \" minutes\" in duration \"15 minutes\"")
		})

		t.Run("unknown contract", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			params := DrawUpContractRequest{
				Language: ContractLanguage("EN"),
				Type:     ContractType("UnknownContractName"),
				Version:  ContractVersion("v3"),
			}
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.EqualError(t, err, "no contract found for given combination of type, version, and language")
		})

		t.Run("malformed orgID", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			params := DrawUpContractRequest{
				Language:    ContractLanguage("EN"),
				Type:        ContractType("PractitionerLogin"),
				Version:     ContractVersion("v3"),
				LegalEntity: LegalEntity("ZorgId:15"),
			}
			bindPostBody(ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.ErrorIs(t, err, did.ErrInvalidDID)
		})

	})

	t.Run("nok - error while drawing up contract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := DrawUpContractRequest{
			Language:    ContractLanguage("EN"),
			Type:        ContractType("PractitionerLogin"),
			Version:     ContractVersion("v3"),
			LegalEntity: LegalEntity(vdr.TestDIDA.String()),
		}
		bindPostBody(ctx, params)

		ctx.notaryMock.EXPECT().DrawUpContract(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("unknown error while drawing up the contract"))

		err := ctx.wrapper.DrawUpContract(ctx.echoMock)

		assert.EqualError(t, err, "unknown error while drawing up the contract")
	})
}

func TestWrapper_CreateJwtBearerToken(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateJwtBearerTokenRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	expectStatusOK := func(ctx *TestContext, response JwtBearerTokenResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)
	}

	t.Run("make request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		subj := "urn:oid:2.16.840.1.113883.2.4.6.3:9999990"
		body := CreateJwtBearerTokenRequest{
			Actor:     "urn:oid:2.16.840.1.113883.2.4.6.1:48000000",
			Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			Subject:   &subj,
			Identity:  "irma-token",
			Service:   "service",
		}
		bindPostBody(ctx, body)
		response := JwtBearerTokenResponse{
			BearerToken: "123.456.789",
		}

		expectedRequest := services.CreateJwtBearerTokenRequest{
			Actor:         body.Actor,
			Custodian:     body.Custodian,
			IdentityToken: &body.Identity,
			Subject:       body.Subject,
			Service:       "service",
		}

		ctx.oauthClientMock.EXPECT().CreateJwtBearerToken(expectedRequest).Return(&services.JwtBearerTokenResult{BearerToken: response.BearerToken}, nil)
		expectStatusOK(ctx, response)

		if !assert.Nil(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
			t.FailNow()
		}
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
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		errorDescription := "oh boy"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errOauthInvalidRequest}
		expectError(ctx, errorResponse)

		ctx.oauthClientMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(nil, fmt.Errorf("oh boy"))
		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		pkgResponse := &services.AccessTokenResult{AccessToken: "foo"}
		ctx.oauthClientMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(pkgResponse, nil)

		apiResponse := AccessTokenResponse{AccessToken: pkgResponse.AccessToken}
		expectStatusOK(ctx, apiResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)

	})
}

func TestWrapper_VerifyAccessToken(t *testing.T) {
	t.Run("403 - missing header", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		params := VerifyAccessTokenParams{
			Authorization: "",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("403 - incorrect authorization header", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		params := VerifyAccessTokenParams{
			Authorization: "34987569ytihua",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("403 - incorrect token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusForbidden)
		ctx.oauthClientMock.EXPECT().IntrospectAccessToken("token").Return(nil, errors.New("unauthorized"))

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("200 - correct token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusOK)
		ctx.oauthClientMock.EXPECT().IntrospectAccessToken("token").Return(&services.NutsAccessToken{}, nil)

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
		defer ctx.ctrl.Finish()

		request := TokenIntrospectionRequest{Token: ""}
		bindPostBody(ctx, request)

		response := TokenIntrospectionResponse{Active: false}
		expectStatusOK(ctx, response)

		_ = ctx.wrapper.IntrospectAccessToken(ctx.echoMock)
	})

	t.Run("introspect a token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := TokenIntrospectionRequest{Token: "123"}
		bindPostBody(ctx, request)

		aud := "123"
		aid := "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"
		exp := 1581412667
		iat := 1581411767
		iss := "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
		sid := "urn:oid:2.16.840.1.113883.2.4.6.3:999999990"
		service := "service"

		ctx.oauthClientMock.EXPECT().IntrospectAccessToken(request.Token).Return(
			&services.NutsAccessToken{
				Audience:   aud,
				Expiration: int64(exp),
				IssuedAt:   int64(iat),
				Issuer:     iss,
				Subject:    aid,
				SubjectID:  &sid,
				Service:    service,
			}, nil)

		emptyStr := ""
		response := TokenIntrospectionResponse{
			Active: true,
			Aud:    &aud,
			Exp:    &exp,
			Iat:    &iat,
			Iss:    &iss,
			Sid:    &sid,
			Sub:    &aid,
			//Uid:    &uid,
			Service:    &service,
			Email:      &emptyStr,
			GivenName:  &emptyStr,
			Prefix:     &emptyStr,
			FamilyName: &emptyStr,
			Name:       &emptyStr,
		}
		expectStatusOK(ctx, response)

		if !assert.NoError(t, ctx.wrapper.IntrospectAccessToken(ctx.echoMock)) {
			t.Fail()
		}
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
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{
				Context: []string{"http://example.com"},
				Proof:   map[string]interface{}{"foo": "bar"},
				Type:    []string{"TestCredential"},
			}}

		bindPostBody(ctx, postParams)

		verificationResult := &contract.VPVerificationResult{
			Validity:            contract.Valid,
			VPType:              "AVPType",
			DisclosedAttributes: map[string]string{"name": "John"},
			ContractAttributes:  map[string]string{"validTo": "now"},
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
		defer ctx.ctrl.Finish()

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{}}

		bindPostBody(ctx, postParams)

		verificationResult := &contract.VPVerificationResult{
			Validity: contract.Invalid,
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
		defer ctx.ctrl.Finish()

		checkTimeParam := "2021-01-15T09:59:00+01:00"
		postParams := SignatureVerificationRequest{
			CheckTime: &checkTimeParam,
			VerifiablePresentation: VerifiablePresentation{
				Context: []string{"http://example.com"},
				Proof:   map[string]interface{}{"foo": "bar"},
				Type:    []string{"TestCredential"},
			}}

		bindPostBody(ctx, postParams)

		verificationResult := &contract.VPVerificationResult{
			Validity: contract.Valid,
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
		if !assert.NoError(t, err) {
			return
		}

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), &checkTime).Return(verificationResult, nil)
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)

		err = ctx.wrapper.VerifySignature(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - invalid checkTime", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{},
		}

		bindPostBody(ctx, postParams)

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(nil, errors.New("verification error"))

		err := ctx.wrapper.VerifySignature(ctx.echoMock)

		assert.EqualError(t, err, "unable to verify the verifiable presentation: verification error")
	})
}
