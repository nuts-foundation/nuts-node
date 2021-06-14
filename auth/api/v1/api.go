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
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/logging"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ ErrorStatusCodeResolver = (*Wrapper)(nil)

const (
	errOauthInvalidRequest   = "invalid_request"
	errOauthInvalidGrant     = "invalid_grant"
	errOauthUnsupportedGrant = "unsupported_grant_type"
	bearerTokenHeaderPrefix  = "bearer "
)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthenticationServices. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
type Wrapper struct {
	Auth auth.AuthenticationServices
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		services.ErrSessionNotFound: http.StatusNotFound,
		did.ErrInvalidDID:           http.StatusBadRequest,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, w)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, auth.ModuleName)
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
		return err
	}
	rawVP, err := json.Marshal(requestParams.VerifiablePresentation)
	if err != nil {
		return fmt.Errorf("unable to convert the verifiable presentation: %w", err)
	}

	checkTime := time.Now()
	if requestParams.CheckTime != nil {
		checkTime, err = time.Parse(time.RFC3339, *requestParams.CheckTime)
		if err != nil {
			return core.InvalidInputError("could not parse checkTime: %w", err)
		}
	}
	validationResult, err := w.Auth.ContractClient().VerifyVP(rawVP, &checkTime)
	if err != nil {
		return core.InvalidInputError("unable to verify the verifiable presentation: %w", err)
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
	requestParams := new(SignSessionRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return core.InvalidInputError("could not parse request body: %w", err)
	}
	createSessionRequest := services.CreateSessionRequest{
		SigningMeans: contract.SigningMeans(requestParams.Means),
		Message:      requestParams.Payload,
	}
	sessionPtr, err := w.Auth.ContractClient().CreateSigningSession(createSessionRequest)
	if err != nil {
		return core.InvalidInputError("unable to create sign challenge: %w", err)
	}

	var keyValPointer map[string]interface{}
	err = convertToMap(sessionPtr, &keyValPointer)
	if err != nil {
		return core.InvalidInputError("unable to build sessionPointer: %w", err)
	}

	response := SignSessionResponse{
		SessionID:  sessionPtr.SessionID(),
		Means:      SignSessionResponseMeans(requestParams.Means),
		SessionPtr: keyValPointer,
	}
	return ctx.JSON(http.StatusCreated, response)
}

// GetSignSessionStatus handles the http requests for getting the current status of a signing session.
func (w Wrapper) GetSignSessionStatus(ctx echo.Context, sessionID string) error {
	sessionStatus, err := w.Auth.ContractClient().SigningSessionStatus(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session status for %s, reason: %w", sessionID, err)
	}
	vp, err := sessionStatus.VerifiablePresentation()
	if err != nil {
		return fmt.Errorf("error while building verifiable presentation: %w", err)
	}
	var apiVp *VerifiablePresentation
	if vp != nil {
		apiVp = &VerifiablePresentation{}
		err = convertToMap(vp, apiVp)
		if err != nil {
			return fmt.Errorf("unable to convert verifiable presentation: %w", err)
		}
	}
	response := SignSessionStatusResponse{Status: sessionStatus.Status(), VerifiablePresentation: apiVp}
	return ctx.JSON(http.StatusOK, response)
}

// GetContractByType handles the http request for finding a contract by type.
func (w Wrapper) GetContractByType(ctx echo.Context, contractType string, params GetContractByTypeParams) error {
	// convert generated data types to internal types
	var (
		contractLanguage contract.Language
		contractVersion  contract.Version
	)
	if params.Language != nil {
		contractLanguage = contract.Language(*params.Language)
	}

	if params.Version != nil {
		contractVersion = contract.Version(*params.Version)
	}

	// get contract
	authContract := contract.StandardContractTemplates.Get(contract.Type(contractType), contractLanguage, contractVersion)
	if authContract == nil {
		return core.NotFoundError("could not find contract template")
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           ContractLanguage(authContract.Language),
		Template:           &authContract.Template,
		TemplateAttributes: &authContract.TemplateAttributes,
		Type:               ContractType(authContract.Type),
		Version:            ContractVersion(authContract.Version),
	}

	return ctx.JSON(http.StatusOK, answer)
}

// DrawUpContract handles the http request for drawing up a contract for a given contract template identified by type, language and version.
func (w Wrapper) DrawUpContract(ctx echo.Context) error {
	params := new(DrawUpContractRequest)
	if err := ctx.Bind(params); err != nil {
		return err
	}

	var (
		vf            time.Time
		validDuration time.Duration
		err           error
	)
	if params.ValidFrom != nil {
		vf, err = time.Parse(time.RFC3339, *params.ValidFrom)
		if err != nil {
			return core.InvalidInputError("could not parse validFrom: %w", err)
		}
	} else {
		vf = time.Now()
	}

	if params.ValidDuration != nil {
		validDuration, err = time.ParseDuration(*params.ValidDuration)
		if err != nil {
			return core.InvalidInputError("could not parse validDuration: %w", err)
		}
	}

	template := contract.StandardContractTemplates.Get(contract.Type(params.Type), contract.Language(params.Language), contract.Version(params.Version))
	if template == nil {
		return core.NotFoundError("no contract found for given combination of type, version, and language")
	}
	orgID, err := did.ParseDID(string(params.LegalEntity))
	if err != nil {
		return core.InvalidInputError("invalid value '%s' for param legalEntity: %w", params.LegalEntity, err)
	}

	drawnUpContract, err := w.Auth.ContractNotary().DrawUpContract(*template, *orgID, vf, validDuration)
	if err != nil {
		return err
	}

	response := ContractResponse{
		Language: ContractLanguage(drawnUpContract.Template.Language),
		Message:  drawnUpContract.RawContractText,
		Type:     ContractType(drawnUpContract.Template.Type),
		Version:  ContractVersion(drawnUpContract.Template.Version),
	}
	return ctx.JSON(http.StatusOK, response)
}

// CreateJwtBearerToken handles the http request (from from the vendor's EPD/XIS) for creating a JWT bearer token which can be used to retrieve an access token from a remote Nuts node.
func (w Wrapper) CreateJwtBearerToken(ctx echo.Context) error {
	requestBody := &CreateJwtBearerTokenRequest{}
	if err := ctx.Bind(requestBody); err != nil {
		return err
	}

	request := services.CreateJwtBearerTokenRequest{
		Actor:         requestBody.Actor,
		Custodian:     requestBody.Custodian,
		IdentityToken: &requestBody.Identity,
		Service:       requestBody.Service,
		Subject:       requestBody.Subject,
	}
	response, err := w.Auth.OAuthClient().CreateJwtBearerToken(request)
	if err != nil {
		return core.InvalidInputError(err.Error())
	}

	return ctx.JSON(http.StatusOK, JwtBearerTokenResponse{BearerToken: response.BearerToken})
}

// CreateAccessToken handles the http request (from a remote vendor's Nuts node) for creating an access token for accessing
// resources of the local vendor's EPD/XIS. It consumes a JWT Bearer token.
// It consumes and checks the JWT and returns a smaller sessionToken
// The errors returns for this API do not follow RFC7807 but follow the oauth framework error response: RFC6749 (https://tools.ietf.org/html/rfc6749#page-45)
func (w Wrapper) CreateAccessToken(ctx echo.Context) (err error) {
	// Can't use echo.Bind() here since it requires extra tags on generated code
	request := new(CreateAccessTokenRequest)
	request.Assertion = ctx.FormValue("assertion")
	request.GrantType = ctx.FormValue("grant_type")

	if request.GrantType != auth.JwtBearerGrantType {
		errDesc := fmt.Sprintf("grant_type must be: '%s'", auth.JwtBearerGrantType)
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthUnsupportedGrant, ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}

	const jwtPattern = `^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`
	if matched, err := regexp.Match(jwtPattern, []byte(request.Assertion)); !matched || err != nil {
		errDesc := "Assertion must be a valid encoded jwt"
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthInvalidGrant, ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}

	catRequest := services.CreateAccessTokenRequest{RawJwtBearerToken: request.Assertion}
	acResponse, err := w.Auth.OAuthClient().CreateAccessToken(catRequest)
	if err != nil {
		errDesc := err.Error()
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthInvalidRequest, ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}
	response := AccessTokenResponse{AccessToken: acResponse.AccessToken}

	return ctx.JSON(http.StatusOK, response)
}

// VerifyAccessToken handles the http request (from the vendor's EPD/XIS) for verifying an access token received from a remote Nuts node.
func (w Wrapper) VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error {
	if len(params.Authorization) == 0 {
		logging.Log().Warn("No authorization header given")
		return ctx.NoContent(http.StatusForbidden)
	}

	index := strings.Index(strings.ToLower(params.Authorization), bearerTokenHeaderPrefix)
	if index != 0 {
		logging.Log().Warn("Authorization does not contain bearer token")
		return ctx.NoContent(http.StatusForbidden)
	}

	token := params.Authorization[len(bearerTokenHeaderPrefix):]

	_, err := w.Auth.OAuthClient().IntrospectAccessToken(token)
	if err != nil {
		logging.Log().WithError(err).Warn("Error while inspecting access token")
		return ctx.NoContent(http.StatusForbidden)
	}

	return ctx.NoContent(200)
}

// IntrospectAccessToken handles the http request (from the vendor's EPD/XIS) for introspecting an access token received from a remote Nuts node.
func (w Wrapper) IntrospectAccessToken(ctx echo.Context) error {
	token := ctx.FormValue("token")

	introspectionResponse := TokenIntrospectionResponse{
		Active: false,
	}

	if len(token) == 0 {
		return ctx.JSON(http.StatusOK, introspectionResponse)
	}

	claims, err := w.Auth.OAuthClient().IntrospectAccessToken(token)
	if err != nil {
		logging.Log().WithError(err).Warn("Error while inspecting access token")
		return ctx.JSON(http.StatusOK, introspectionResponse)
	}

	exp := int(claims.Expiration)
	iat := int(claims.IssuedAt)

	introspectionResponse = TokenIntrospectionResponse{
		Active:     true,
		Sub:        &claims.Subject,
		Iss:        &claims.Issuer,
		Aud:        &claims.Audience,
		Exp:        &exp,
		Iat:        &iat,
		Sid:        claims.SubjectID,
		Service:    &claims.Service,
		Name:       &claims.Name,
		GivenName:  &claims.GivenName,
		Prefix:     &claims.Prefix,
		FamilyName: &claims.FamilyName,
		Email:      &claims.Email,
	}

	return ctx.JSON(http.StatusOK, introspectionResponse)
}

// convertToMap converts an object to a map[string]interface{} using json conversion
func convertToMap(obj interface{}, target interface{}) error {
	jsonStr, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("could not convert value to json: %w", err)
	}
	if err := json.Unmarshal(jsonStr, target); err != nil {
		return fmt.Errorf("could not convert json string to key value map: %w", err)
	}
	return nil
}
