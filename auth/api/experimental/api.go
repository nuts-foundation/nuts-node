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
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

var _ ServerInterface = (*Wrapper)(nil)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthenticationServices. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
//
// This is the experimental API. It is used to tests APIs is the wild.
type Wrapper struct {
	Auth auth.AuthenticationServices
}

// Routes registers the Echo routes for the API.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// VerifySignature handles the VerifySignature http request.
// It parses the request body, parses the verifiable presentation and calls the ContractClient to verify the VP.
func (w Wrapper) VerifySignature(ctx echo.Context) error {
	requestParams := new(SignatureVerificationRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse request body: %s", err.Error()))
	}
	rawVP, err := json.Marshal(requestParams.VerifiablePresentation)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert the verifiable presentation: %s", err.Error()))
	}

	checkTime := time.Now()
	if requestParams.CheckTime != nil {
		checkTime, err = time.Parse(time.RFC3339, *requestParams.CheckTime)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse checkTime: %s", err.Error()))
		}
	}
	validationResult, err := w.Auth.ContractClient().VerifyVP(rawVP, &checkTime)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to verify the verifiable presentation: %s", err.Error()))
	}
	// Convert internal validationResult to api SignatureVerificationResponse
	response := SignatureVerificationResponse{}
	if validationResult.Validity == contract.Valid {
		response.Validity = true

		credentials := map[string]interface{}{}
		for key, val := range validationResult.ContractAttributes {
			credentials[key] = val
		}
		response.Credentials = &credentials

		issuerAttributes := map[string]interface{}{}
		for key, val := range validationResult.DisclosedAttributes {
			issuerAttributes[key] = val
		}
		response.IssuerAttributes = &issuerAttributes

		vpType := string(validationResult.VPType)
		response.VpType = &vpType
	} else {
		response.Validity = false
	}
	return ctx.JSON(http.StatusOK, response)
}

// CreateSignSession handles the CreateSignSession http request. It parses the parameters, finds the means handler and returns a session pointer which can be used to monitor the session.
func (w Wrapper) CreateSignSession(ctx echo.Context) error {
	requestParams := new(CreateSignSessionRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse request body: %s", err.Error()))
	}
	createSessionRequest := services.CreateSessionRequest{
		SigningMeans: contract.SigningMeans(requestParams.Means),
		Message:      requestParams.Payload,
	}
	sessionPtr, err := w.Auth.ContractClient().CreateSigningSession(createSessionRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to create sign challenge: %s", err.Error()))
	}

	var keyValPointer map[string]interface{}
	err = convertToMap(sessionPtr, &keyValPointer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to build sessionPointer: %s", err.Error()))
	}

	response := CreateSignSessionResponse{
		SessionID:  sessionPtr.SessionID(),
		Means:      requestParams.Means,
		SessionPtr: keyValPointer,
	}
	return ctx.JSON(http.StatusCreated, response)
}

// GetSignSessionStatus handles the http requests for getting the current status of a signing session.
func (w Wrapper) GetSignSessionStatus(ctx echo.Context, sessionID string) error {
	sessionStatus, err := w.Auth.ContractClient().SigningSessionStatus(sessionID)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("no active signing session for sessionID: '%s' found", sessionID))
		}
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to retrieve a session status: %s", err.Error()))
	}
	vp, err := sessionStatus.VerifiablePresentation()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while building verifiable presentation: %s", err.Error()))
	}
	var apiVp *VerifiablePresentation
	if vp != nil {
		apiVp = &VerifiablePresentation{}
		err = convertToMap(vp, apiVp)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert verifiable presentation: %s", err.Error()))
		}
	}
	response := GetSignSessionStatusResponse{Status: sessionStatus.Status(), VerifiablePresentation: apiVp}
	return ctx.JSON(http.StatusOK, response)
}

// DrawUpContract handles the http request for drawing up a contract for a given contract template identified by type, language and version.
func (w Wrapper) DrawUpContract(ctx echo.Context) error {
	params := new(DrawUpContractRequest)
	if err := ctx.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse request body: %s", err.Error()))
	}

	var (
		vf            time.Time
		validDuration time.Duration
		err           error
	)
	if params.ValidFrom != nil {
		vf, err = time.Parse("2006-01-02T15:04:05-07:00", *params.ValidFrom)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse validFrom: %s", err.Error()))
		}
	} else {
		vf = time.Now()
	}

	if params.ValidDuration != nil {
		validDuration, err = time.ParseDuration(*params.ValidDuration)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not parse validDuration: %s", err.Error()))
		}
	}

	template := contract.StandardContractTemplates.Get(contract.Type(params.Type), contract.Language(params.Language), contract.Version(params.Version))
	if template == nil {
		return echo.NewHTTPError(http.StatusNotFound, "no contract found for given combination of type, version and language")
	}
	orgID, err := did.ParseDID(string(params.LegalEntity))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid value for param legalEntity: '%s'", params.LegalEntity))
	}

	drawnUpContract, err := w.Auth.ContractNotary().DrawUpContract(*template, *orgID, vf, validDuration)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("error while drawing up the contract: %s", err.Error()))
	}

	response := ContractResponse{
		Language: ContractLanguage(drawnUpContract.Template.Language),
		Message:  drawnUpContract.RawContractText,
		Type:     ContractType(drawnUpContract.Template.Type),
		Version:  ContractVersion(drawnUpContract.Template.Version),
	}
	return ctx.JSON(http.StatusOK, response)

}

// convertToMap converts an object to a map[string]interface{} using json conversion
func convertToMap(obj interface{}, target interface{}) (err error) {
	var jsonStr []byte
	jsonStr, err = json.Marshal(obj)
	if err != nil {
		fmt.Errorf("could not convert value to json: %w", err)
	}

	err = json.Unmarshal(jsonStr, target)
	if err != nil {
		fmt.Errorf("could not convert json string to key value map: %w", err)
	}
	return
}
