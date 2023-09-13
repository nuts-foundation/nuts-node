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
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/types"
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

func (r Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// resolve wallet
	requestHolder, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("did not found: %w", err)
	}
	isWallet, err := r.vdr.IsOwner(ctx, *requestHolder)
	if err != nil {
		return nil, err
	}
	if !isWallet {
		return nil, core.InvalidInputError("did not owned by this node: %w", err)
	}

	// resolve verifier metadata
	requestVerifier, err := did.ParseDID(request.Body.Verifier)
	if err != nil {
		return nil, core.InvalidInputError("invalid verifier: %w", err)
	}
	_, _, err = r.vdr.Resolver().Resolve(*requestVerifier, nil)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return nil, core.InvalidInputError("verifier not found: %w", err)
		}
		return nil, err
	}

	// todo fetch metadata using didDocument service data or .well-known path

	return RequestAccessToken200JSONResponse{}, nil
}
