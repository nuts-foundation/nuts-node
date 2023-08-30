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
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
)

// serviceToService adds support for service-to-service OAuth2 flows,
// which uses a custom vp_token grant to authenticate calls to the token endpoint.
// Clients first call the presentation definition endpoint to get a presentation definition for the desired scope,
// then create a presentation submission given the definition which is posted to the token endpoint as vp_token.
// The AS then returns an access token with the requested scope.
// Requires:
// - GET /presentation_definition?scope=... (returns a presentation definition)
// - POST /token (with vp_token grant)
type serviceToService struct {
}

func (s serviceToService) Routes(router core.EchoRouter) {
	router.Add("GET", "/public/oauth2/:did/presentation_definition", func(echoCtx echo.Context) error {
		// TODO: Read scope, map to presentation definition, return
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
}

func (s serviceToService) validateVPToken(params map[string]string) (string, error) {
	submission := params["presentation_submission"]
	scope := params["scope"]
	vp_token := params["vp_token"]
	if submission == "" || scope == "" || vp_token == "" {
		// TODO: right error response
		return "", errors.New("missing required parameters")
	}
	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2418
	// TODO: verify parameters
	return scope, nil
}

func (s serviceToService) handleAuthzRequest(_ map[string]string, _ *Session) (*authzResponse, error) {
	// Protocol does not support authorization code flow
	return nil, nil
}
