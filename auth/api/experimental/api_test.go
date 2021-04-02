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

package experimental

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
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
	wrapper            Wrapper
}

type mockAuthClient struct {
	ctrl               *gomock.Controller
	mockContractClient *services.MockContractClient
	mockContractNotary *services.MockContractNotary
}

func (m *mockAuthClient) OAuthClient() services.OAuthClient {
	panic("implement me")
}

func (m *mockAuthClient) ContractClient() services.ContractClient {
	return m.mockContractClient
}

func (m *mockAuthClient) ContractNotary() services.ContractNotary {
	return m.mockContractNotary
}

func createContext(t *testing.T) TestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockContractClient := services.NewMockContractClient(ctrl)
	mockContractNotary := services.NewMockContractNotary(ctrl)
	authMock := &mockAuthClient{ctrl: ctrl, mockContractClient: mockContractClient, mockContractNotary: mockContractNotary}
	return TestContext{
		ctrl:               ctrl,
		echoMock:           mock.NewMockContext(ctrl),
		authMock:           authMock,
		notaryMock:         mockContractNotary,
		contractClientMock: mockContractClient,
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

		response := GetSignSessionStatusResponse{
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

		response := GetSignSessionStatusResponse{
			Status:                 signingSessionStatus,
			VerifiablePresentation: &VerifiablePresentation{Context: []string{"http://example.com"}},
		}

		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.NoError(t, err)
	})

	t.Run("nok - session not found", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		signingSessionID := "123"
		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(nil, services.ErrSessionNotFound)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)
		assert.Equal(t, "no active signing session for sessionID: '123' found", httpError.Message)
	})

	t.Run("nok - unable to build a VP", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		signingSessionID := "123"
		signingSessionResult := contract.NewMockSigningSessionResult(ctx.ctrl)

		signingSessionResult.EXPECT().VerifiablePresentation().Return(nil, errors.New("could not build VP"))

		ctx.contractClientMock.EXPECT().SigningSessionStatus(signingSessionID).Return(signingSessionResult, nil)

		err := ctx.wrapper.GetSignSessionStatus(ctx.echoMock, signingSessionID)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusInternalServerError, httpError.Code)
		assert.Equal(t, "error while building verifiable presentation: could not build VP", httpError.Message)
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

		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)

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
		bindPostBody(&ctx, params)

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

			validFrom := "invalid date"

			params := DrawUpContractRequest{
				ValidFrom: &validFrom,
			}
			bindPostBody(&ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.IsType(t, &echo.HTTPError{}, err)
			httpError := err.(*echo.HTTPError)
			assert.Equal(t, http.StatusBadRequest, httpError.Code)
			assert.Equal(t, "could not parse validFrom: parsing time \"invalid date\" as \"2006-01-02T15:04:05-07:00\": cannot parse \"invalid date\" as \"2006\"", httpError.Message)
		})

		t.Run("invalid formatted duration", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			duration := "15 minutes"

			params := DrawUpContractRequest{
				ValidDuration: &duration,
			}
			bindPostBody(&ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.IsType(t, &echo.HTTPError{}, err)
			httpError := err.(*echo.HTTPError)
			assert.Equal(t, http.StatusBadRequest, httpError.Code)
			assert.Equal(t, "could not parse validDuration: time: unknown unit \" minutes\" in duration \"15 minutes\"", httpError.Message)
		})

		t.Run("unknown contract", func(t *testing.T) {
			ctx := createContext(t)
			defer ctx.ctrl.Finish()

			params := DrawUpContractRequest{
				Language: ContractLanguage("EN"),
				Type:     ContractType("UnknownContractName"),
				Version:  ContractVersion("v3"),
			}
			bindPostBody(&ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.IsType(t, &echo.HTTPError{}, err)
			httpError := err.(*echo.HTTPError)
			assert.Equal(t, http.StatusNotFound, httpError.Code)
			assert.Equal(t, "no contract found for given combination of type, version and language", httpError.Message)
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
			bindPostBody(&ctx, params)

			err := ctx.wrapper.DrawUpContract(ctx.echoMock)

			assert.IsType(t, &echo.HTTPError{}, err)
			httpError := err.(*echo.HTTPError)
			assert.Equal(t, http.StatusBadRequest, httpError.Code)
			assert.Equal(t, "invalid value for param legalEntity: 'ZorgId:15'", httpError.Message)
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
		bindPostBody(&ctx, params)

		ctx.notaryMock.EXPECT().DrawUpContract(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("unknown error while drawing up the contract"))

		err := ctx.wrapper.DrawUpContract(ctx.echoMock)

		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
		assert.Equal(t, "error while drawing up the contract: unknown error while drawing up the contract", httpError.Message)
	})
}

type signSessionResponseMatcher struct {
	means string
}

func (s signSessionResponseMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	return x.(CreateSignSessionResponse).Means == s.means && x.(CreateSignSessionResponse).SessionPtr["sessionID"] != ""
}

func (s signSessionResponseMatcher) String() string {
	return fmt.Sprintf("{%v somePtr}", s.means)
}

func TestWrapper_CreateSignSession(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateSignSessionRequest) {
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

		postParams := CreateSignSessionRequest{
			Means:   "dummy",
			Payload: "this is the contract message to agree to",
		}
		bindPostBody(&ctx, postParams)

		ctx.echoMock.EXPECT().JSON(http.StatusCreated, signSessionResponseMatcher{means: "dummy"})
		err := ctx.wrapper.CreateSignSession(ctx.echoMock)
		assert.NoError(t, err)
	})

	t.Run("nok - error while creating signing session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		postParams := CreateSignSessionRequest{}
		bindPostBody(&ctx, postParams)

		ctx.contractClientMock.EXPECT().CreateSigningSession(gomock.Any()).Return(nil, errors.New("some error"))

		err := ctx.wrapper.CreateSignSession(ctx.echoMock)

		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
		assert.Equal(t, "unable to create sign challenge: some error", httpError.Message)
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

		bindPostBody(&ctx, postParams)

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

		bindPostBody(&ctx, postParams)

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

		bindPostBody(&ctx, postParams)

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

		bindPostBody(&ctx, postParams)

		err := ctx.wrapper.VerifySignature(ctx.echoMock)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "code=400, message=could not parse checkTime: parsing time \"invalid formatted timestamp\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"invalid formatted timestamp\" as \"2006\"", err.Error())
	})

	t.Run("nok - verification returns an error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		postParams := SignatureVerificationRequest{
			VerifiablePresentation: VerifiablePresentation{},
		}

		bindPostBody(&ctx, postParams)

		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), gomock.Any()).Return(nil, errors.New("verification error"))

		err := ctx.wrapper.VerifySignature(ctx.echoMock)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, `code=400, message=unable to verify the verifiable presentation: verification error`, err.Error())
	})
}
