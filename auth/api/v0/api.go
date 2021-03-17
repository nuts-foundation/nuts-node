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
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth/logging"
	"github.com/nuts-foundation/nuts-node/core"

	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthenticationServices. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
//
// This wrapper handles the unversioned, so called v0, API requests. Most of them wil be deprecated and moved to a v1 version
type Wrapper struct {
	Auth auth.AuthenticationServices
}

// Routes registers the Echo routes for the API.
func (api *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, api)
}

const errOauthInvalidRequest = "invalid_request"
const errOauthInvalidGrant = "invalid_grant"
const errOauthUnsupportedGrant = "unsupported_grant_type"

// GetContractByType calls the engines GetContractByType and translate the answer to
// the API format and returns the the answer back to the HTTP stack
func (api *Wrapper) GetContractByType(ctx echo.Context, contractType string, params GetContractByTypeParams) error {
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
		return echo.NewHTTPError(http.StatusNotFound, "could not found contract template")
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           Language(authContract.Language),
		Template:           &authContract.Template,
		TemplateAttributes: &authContract.TemplateAttributes,
		Type:               Type(authContract.Type),
		Version:            Version(authContract.Version),
	}

	return ctx.JSON(http.StatusOK, answer)
}

// CreateAccessToken handles the api call to create an access token.
// It consumes and checks the JWT and returns a smaller sessionToken
func (api *Wrapper) CreateAccessToken(ctx echo.Context, params CreateAccessTokenParams) (err error) {
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
	acResponse, err := api.Auth.OAuthClient().CreateAccessToken(catRequest)
	if err != nil {
		errDesc := err.Error()
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthInvalidRequest, ErrorDescription: errDesc}
		return ctx.JSON(http.StatusBadRequest, errorResponse)
	}
	response := AccessTokenResponse{AccessToken: acResponse.AccessToken}

	return ctx.JSON(http.StatusOK, response)
}

// CreateJwtBearerToken fills a CreateJwtBearerTokenRequest from the request body and passes it to the auth module.
func (api *Wrapper) CreateJwtBearerToken(ctx echo.Context) error {
	requestBody := &CreateJwtBearerTokenRequest{}
	if err := ctx.Bind(requestBody); err != nil {
		return err
	}

	request := services.CreateJwtBearerTokenRequest{
		Actor:         requestBody.Actor,
		Custodian:     requestBody.Custodian,
		IdentityToken: &requestBody.Identity,
		Subject:       requestBody.Subject,
	}
	response, err := api.Auth.OAuthClient().CreateJwtBearerToken(request)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	return ctx.JSON(http.StatusOK, JwtBearerTokenResponse{BearerToken: response.BearerToken})
}

// IntrospectAccessToken takes the access token from the request form value and passes it to the auth client.
func (api *Wrapper) IntrospectAccessToken(ctx echo.Context) error {
	token := ctx.FormValue("token")

	introspectionResponse := TokenIntrospectionResponse{
		Active: false,
	}

	if len(token) == 0 {
		return ctx.JSON(http.StatusOK, introspectionResponse)
	}

	claims, err := api.Auth.OAuthClient().IntrospectAccessToken(token)
	if err != nil {
		logging.Log().WithError(err).Debug("Error while inspecting access token")
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
		Scope:      &claims.Scope,
		Name:       &claims.Name,
		GivenName:  &claims.GivenName,
		Prefix:     &claims.Prefix,
		FamilyName: &claims.FamilyName,
		Email:      &claims.Email,
	}

	return ctx.JSON(http.StatusOK, introspectionResponse)
}

const bearerPrefix = "bearer "

// VerifyAccessToken verifies if a request contains a valid bearer token issued by this server
func (api *Wrapper) VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error {
	if len(params.Authorization) == 0 {
		logging.Log().Warn("No authorization header given")
		return ctx.NoContent(http.StatusForbidden)
	}

	index := strings.Index(strings.ToLower(params.Authorization), bearerPrefix)
	if index != 0 {
		logging.Log().Warn("Authorization does not contain bearer token")
		return ctx.NoContent(http.StatusForbidden)
	}

	token := params.Authorization[len(bearerPrefix):]

	_, err := api.Auth.OAuthClient().IntrospectAccessToken(token)
	if err != nil {
		logging.Log().WithError(err).Warn("Error while inspecting access token")
		return ctx.NoContent(http.StatusForbidden)
	}

	return ctx.NoContent(200)
}
