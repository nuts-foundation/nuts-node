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

package v0

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/sirupsen/logrus"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/validator"

	irmaService "github.com/nuts-foundation/nuts-node/auth/services/irma"

	"github.com/nuts-foundation/nuts-node/auth/contract"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_NutsAuthCreateSession(t *testing.T) {
	t.Run("with valid params", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tt := time.Now().Truncate(time.Second)
		vf := tt.Format("2006-01-02T15:04:05-07:00")
		vt := tt.Add(time.Hour * 13).Format("2006-01-02T15:04:05-07:00")
		d := tt.Add(time.Hour * 13).Sub(tt)

		ctx.notaryMock.EXPECT().DrawUpContract(gomock.Any(), gomock.Any(), gomock.Any(), d).Return(
			&contract.Contract{
				RawContractText: "NL:BehandelaarLogin:v3 Ondergetekende geeft toestemming aan ZorgDossier om namens Verpleeghuis de Hoeksteen en ondergetekende het Nuts netwerk te bevragen",
				Template:        nil,
				Params:          nil,
			}, nil)

		ctx.contractMock.EXPECT().CreateSigningSession(services.CreateSessionRequest{
			Message:      "NL:BehandelaarLogin:v3 Ondergetekende geeft toestemming aan ZorgDossier om namens Verpleeghuis de Hoeksteen en ondergetekende het Nuts netwerk te bevragen",
			SigningMeans: "irma",
		}).Return(irmaService.SessionPtr{
			QrCodeInfo: irma.Qr{
				URL:  "http://example.com" + irmaService.IrmaMountPath + "/123",
				Type: "signing"},
			ID: "abc-sessionid",
		}, nil)

		wrapper := Wrapper{Auth: ctx.authMock}
		params := ContractSigningRequest{
			Type:        "BehandelaarLogin",
			Language:    "NL",
			Version:     "v3",
			ValidFrom:   &vf,
			ValidTo:     &vt,
			LegalEntity: LegalEntity(vdr.RandomDID.String()),
		}

		jsonData, _ := json.Marshal(params)

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
		ctx.echoMock.EXPECT().JSON(http.StatusCreated, CreateSessionResult{
			QrCodeInfo: IrmaQR{U: "http://example.com" + irmaService.IrmaMountPath + "/123",
				Irmaqr: "signing",
			}, SessionId: "abc-sessionid"})

		err := wrapper.CreateSession(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("with malformed time period", func(t *testing.T) {
		wrapper := Wrapper{}
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		jsonData := `{"language":"NL","legalEntity":"legalEntity","type":"BehandelaarLogin","valid_from":"invalid time in valid_from","valid_to":"2020-03-26T00:16:57+01:00","version":"v1"}`

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(jsonData), f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Contains(t, httpError.Message, "could not parse validFrom")
		assert.Equal(t, http.StatusBadRequest, httpError.Code)

		jsonData = `{"language":"NL","legalEntity":"legalEntity","type":"BehandelaarLogin","valid_from":"2020-03-26T00:16:57+01:00","valid_to":"invalid time in validTo","version":"v1"}`

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(jsonData), f)
		})

		err = wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError = err.(*echo.HTTPError)
		assert.Contains(t, httpError.Message, "could not parse validTo")
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("with invalid params", func(t *testing.T) {
		wrapper := Wrapper{}
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Return(errors.New("unable to parse body"))
		err := wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("with an unknown contract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "UnknownContract",
			Language:    "NL",
			Version:     "v1",
			LegalEntity: LegalEntity(vdr.RandomDID.String()),
		}

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
		assert.Equal(t, "Unable to find contract: UnknownContract", httpError.Message)
	})

	t.Run("for an unknown legalEntity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "BehandelaarLogin",
			Language:    "NL",
			Version:     "v3",
			LegalEntity: LegalEntity(vdr.RandomDID.String()),
		}

		ctx.notaryMock.EXPECT().DrawUpContract(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
		assert.Equal(t, "Unable to draw up contract: not found", httpError.Message)
	})

	t.Run("for an unregistered legal entity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "BehandelaarLogin",
			Language:    "NL",
			Version:     "v3",
			LegalEntity: LegalEntity(vdr.RandomDID.String()),
		}

		ctx.notaryMock.EXPECT().DrawUpContract(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, validator.ErrMissingOrganizationKey)

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
		assert.Equal(t, "Unknown legalEntity, this Nuts node does not seem to be managing 'did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW'", httpError.Message)
	})
}

func TestWrapper_NutsAuthSessionRequestStatus(t *testing.T) {
	t.Run("get status of a known session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		sessionID := "123"
		nutsAuthToken := "123.456.123"
		proofStatus := "VALID"

		ctx.contractMock.EXPECT().ContractSessionStatus(sessionID).Return(&services.SessionStatusResult{
			SessionResult: server.SessionResult{
				Status: "INITIALIZED",
				Token:  "YRnWbPJ7ffKCnf9cP51e",
				Type:   "signing",
				Disclosed: [][]*irma.DisclosedAttribute{
					{{Value: map[string]string{"nl": "00000001"}}},
				},
				ProofStatus: irma.ProofStatusValid,
			},
			NutsAuthToken: nutsAuthToken,
		}, nil)

		a := []DisclosedAttribute{
			{
				Value: map[string]interface{}{"nl": "00000001"},
			},
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, SessionResult{
			Status:        "INITIALIZED",
			Token:         "YRnWbPJ7ffKCnf9cP51e",
			Type:          "signing",
			Disclosed:     &a,
			NutsAuthToken: &nutsAuthToken,
			ProofStatus:   &proofStatus,
		})
		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.SessionRequestStatus(ctx.echoMock, sessionID)
		assert.Nil(t, err)
	})

	t.Run("try to get a status of an unknown session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		sessionID := "123"

		ctx.contractMock.EXPECT().ContractSessionStatus(sessionID).Return(nil, services.ErrSessionNotFound)
		wrapper := Wrapper{Auth: ctx.authMock}

		err := wrapper.SessionRequestStatus(ctx.echoMock, sessionID)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)
	})
}

func TestWrapper_NutsAuthValidateContract(t *testing.T) {
	t.Run("ValidateContract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ValidationRequest{
			ContractFormat: "JWT",
			ContractString: "base64encodedContractString",
		}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		sa := map[string]interface{}{"nl": "00000007"}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, ValidationResult{
			ContractFormat:   string(services.JwtFormat),
			ValidationResult: "VALID",
			SignerAttributes: sa,
		})

		ctx.contractMock.EXPECT().ValidateContract(services.ValidationRequest{
			ContractFormat: services.JwtFormat,
			ContractString: "base64encodedContractString",
		}).Return(&services.ContractValidationResult{
			ValidationResult:    "VALID",
			ContractFormat:      services.JwtFormat,
			DisclosedAttributes: map[string]string{"nl": "00000007"},
		}, nil)

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.ValidateContract(ctx.echoMock)

		assert.Nil(t, err)
	})

}

func TestWrapper_NutsAuthGetContractByType(t *testing.T) {
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
			Language:           Language(a.Language),
			Template:           &a.Template,
			TemplateAttributes: &a.TemplateAttributes,
			Type:               Type(a.Type),
			Version:            Version(a.Version),
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

		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)

	})
}

type OAuthErrorMatcher struct {
	x AccessTokenRequestFailedResponse
}

func (e OAuthErrorMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	response := x.(AccessTokenRequestFailedResponse)
	return e.x.Error == response.Error && e.x.ErrorDescription == response.ErrorDescription
}

func (e OAuthErrorMatcher) String() string {
	return fmt.Sprintf("is equal to {%v, %v}", e.x.Error, e.x.ErrorDescription)
}

type TestContext struct {
	ctrl         *gomock.Controller
	echoMock     *mock.MockContext
	authMock     *auth.MockAuthenticationServices
	oauthMock    *services.MockOAuthClient
	notaryMock   *services.MockContractNotary
	contractMock *services.MockContractClient
	wrapper      Wrapper
}

var createContext = func(t *testing.T) *TestContext {
	ctrl := gomock.NewController(t)
	authMock := auth.NewMockAuthenticationServices(ctrl)
	oauthMock := services.NewMockOAuthClient(ctrl)
	notaryMock := services.NewMockContractNotary(ctrl)
	contractMock := services.NewMockContractClient(ctrl)

	authMock.EXPECT().OAuthClient().AnyTimes().Return(oauthMock)
	authMock.EXPECT().ContractClient().AnyTimes().Return(contractMock)
	authMock.EXPECT().ContractNotary().AnyTimes().Return(notaryMock)

	return &TestContext{
		ctrl:         ctrl,
		echoMock:     mock.NewMockContext(ctrl),
		authMock:     authMock,
		oauthMock:    oauthMock,
		contractMock: contractMock,
		notaryMock:   notaryMock,
		wrapper:      Wrapper{Auth: authMock},
	}
}

func TestWrapper_NutsAuthCreateAccessToken(t *testing.T) {
	const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6NDgwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjoxNTc4MTEwNDgxLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.76XtU81IyR3Ak_2fgrYsuLcvxndf0eedT1mFPa-rPXk"

	bindPostBody := func(ctx *TestContext, body CreateAccessTokenRequest) {
		ctx.echoMock.EXPECT().FormValue("assertion").Return(body.Assertion)
		ctx.echoMock.EXPECT().FormValue("grant_type").Return(body.GrantType)
	}

	expectError := func(ctx *TestContext, err AccessTokenRequestFailedResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusBadRequest, OAuthErrorMatcher{x: err})
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

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock, CreateAccessTokenParams{})

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

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock, CreateAccessTokenParams{})

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

		ctx.oauthMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(nil, fmt.Errorf("oh boy"))
		err := ctx.wrapper.CreateAccessToken(ctx.echoMock, CreateAccessTokenParams{XSslClientCert: "cert"})

		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		pkgResponse := &services.AccessTokenResult{AccessToken: "foo"}
		ctx.oauthMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt}).Return(pkgResponse, nil)

		apiResponse := AccessTokenResponse{AccessToken: pkgResponse.AccessToken}
		expectStatusOK(ctx, apiResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock, CreateAccessTokenParams{})

		assert.Nil(t, err)

	})

}

func TestWrapper_NutsAuthCreateJwtBearerToken(t *testing.T) {
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
			Scope:     "nuts-sso",
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
		}

		ctx.oauthMock.EXPECT().CreateJwtBearerToken(expectedRequest).Return(&services.JwtBearerTokenResult{BearerToken: response.BearerToken}, nil)
		expectStatusOK(ctx, response)

		if !assert.Nil(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
			t.FailNow()
		}
	})
}

func TestWrapper_NutsAuthIntrospectAccessToken(t *testing.T) {
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
		scope := "nuts-sso"

		ctx.oauthMock.EXPECT().IntrospectAccessToken(request.Token).Return(
			&services.NutsAccessToken{
				Audience:   aud,
				Expiration: int64(exp),
				IssuedAt:   int64(iat),
				Issuer:     iss,
				Subject:    aid,
				SubjectID:  &sid,
				Scope:      scope,
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
			Scope:      &scope,
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
		ctx.oauthMock.EXPECT().IntrospectAccessToken("token").Return(nil, errors.New("unauthorized"))

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})

	t.Run("200 - correct token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		params := VerifyAccessTokenParams{
			Authorization: "Bearer token",
		}

		ctx.echoMock.EXPECT().NoContent(http.StatusOK)
		ctx.oauthMock.EXPECT().IntrospectAccessToken("token").Return(&services.NutsAccessToken{}, nil)

		_ = ctx.wrapper.VerifyAccessToken(ctx.echoMock, params)
	})
}
