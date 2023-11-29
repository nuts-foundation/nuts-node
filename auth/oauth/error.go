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

package oauth

import (
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"net/url"
	"strings"
)

// ErrorCode specifies error codes as defined by the OAuth2 specifications.
// Codes and descriptions are taken from https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type ErrorCode string

const (
	// InvalidRequest is returned when the request is missing a required parameter, includes an invalid parameter value,
	// includes a parameter more than once, or is otherwise malformed.
	InvalidRequest ErrorCode = "invalid_request"
	// UnsupportedGrantType is returned when the authorization grant type is not supported by the authorization server.
	UnsupportedGrantType ErrorCode = "unsupported_grant_type"
	// UnsupportedResponseType is returned when the authorization server does not support obtaining an authorization code using this method.
	UnsupportedResponseType ErrorCode = "unsupported_response_type"
	// ServerError is returned when the Authorization Server encounters an unexpected condition that prevents it from fulfilling the request.
	ServerError ErrorCode = "server_error"
	// InvalidScope is returned when the requested scope is invalid, unknown or malformed.
	InvalidScope = ErrorCode("invalid_scope")
)

// Make sure the error implements core.HTTPStatusCodeError, so the HTTP request logger can log the correct status code.
var _ core.HTTPStatusCodeError = OAuth2Error{}

// OAuth2Error is an OAuth2 error that signals the error was (probably) caused by the client (e.g. bad request),
// or that the client can recover from the error (e.g. retry).
type OAuth2Error struct {
	// Code is the error code as defined by the OAuth2 specification.
	Code ErrorCode `json:"error"`
	// Description is a human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.
	Description string `json:"error_description,omitempty"`
	// InternalError is the underlying error, may be omitted. It is not intended to be returned to the client, only to be logged.
	InternalError error `json:"-"`
	// RedirectURI is the redirect URI that should be used to redirect the client to, in case the user-agent is a browser.
	// It should not be set if the user-agent is not a browser, or there is no redirect_uri (because the request was malformed), this field is empty.
	// When the field is set, the user-agent is redirected to the specified URI with the error code and description as query parameters.
	// If it's not set, the error code and description are returned in the response body (plain text or JSON).
	RedirectURI string `json:"-"`
}

// StatusCode returns the HTTP status code to be returned to the client, in case the user-agent can't be redirected with HTTP 302 - Found.
func (e OAuth2Error) StatusCode() int {
	switch e.Code {
	case ServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// OAuth2Error returns the error message, which is either the underlying error or the code if there is no underlying error
func (e OAuth2Error) Error() string {
	var parts []string
	parts = append(parts, string(e.Code))
	if e.InternalError != nil {
		parts = append(parts, e.InternalError.Error())
	}
	if e.Description != "" {
		parts = append(parts, e.Description)
	}
	return strings.Join(parts, " - ")
}

// Oauth2ErrorWriter is a HTTP response writer for OAuth errors
type Oauth2ErrorWriter struct{}

func (p Oauth2ErrorWriter) Write(echoContext echo.Context, _ int, _ string, err error) error {
	var oauthErr OAuth2Error
	if !errors.As(err, &oauthErr) {
		// Internal error, wrap it in an OAuth2 error
		oauthErr = OAuth2Error{
			Code:          ServerError,
			InternalError: err,
		}
	}
	if oauthErr.Code == "" {
		// Somebody forgot to set a code
		oauthErr.Code = ServerError
	}
	redirectURI, _ := url.Parse(oauthErr.RedirectURI)
	if oauthErr.RedirectURI == "" || redirectURI == nil {
		// Can't redirect the user-agent back, render error as JSON or plain text (depending on accept/content-type)
		accept := echoContext.Request().Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			// Return JSON response
			return echoContext.JSON(oauthErr.StatusCode(), oauthErr)
		}
		contentType := echoContext.Request().Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			// Return JSON response
			return echoContext.JSON(oauthErr.StatusCode(), oauthErr)
		}
		// Return plain text response
		parts := []string{string(oauthErr.Code)}
		if oauthErr.Description != "" {
			parts = append(parts, oauthErr.Description)
		}
		return echoContext.String(oauthErr.StatusCode(), strings.Join(parts, " - "))
	}
	// Redirect the user-agent back to the client
	query := redirectURI.Query()
	query.Set("error", string(oauthErr.Code))
	if oauthErr.Description != "" {
		query.Set("error_description", oauthErr.Description)
	}
	redirectURI.RawQuery = query.Encode()
	return echoContext.Redirect(http.StatusFound, redirectURI.String())
}

// TestOAuthErrorCode tests if the response is an OAuth2 error with the given code.
// Also returns the unmarshalled OAuth2Error
func TestOAuthErrorCode(responseBody []byte, code ErrorCode) (bool, OAuth2Error) {
	var oauthErr OAuth2Error
	if err := json.Unmarshal(responseBody, &oauthErr); err != nil {
		return false, oauthErr
	}
	return oauthErr.Code == code, oauthErr
}
