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
	"errors"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/audit"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	C crypto.KeyStore
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		crypto.ErrPrivateKeyNotFound: http.StatusBadRequest,
	})
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, crypto.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, crypto.ModuleName, operationID)
		},
	}))
}

func (signRequest SignJwtRequest) validate() error {
	if len(signRequest.Kid) == 0 {
		return errors.New("missing kid")
	}

	if len(signRequest.Claims) == 0 {
		return errors.New("missing claims")
	}

	return nil
}

func (signRequest SignJwsRequest) validate() error {
	if len(signRequest.Kid) == 0 {
		return errors.New("missing kid")
	}
	if signRequest.Headers == nil {
		return errors.New("missing headers")
	}
	if signRequest.Payload == nil {
		return errors.New("missing payload")
	}

	return nil
}

// SignJwt handles api calls for signing a Jwt
func (w *Wrapper) SignJwt(ctx context.Context, signRequest SignJwtRequestObject) (SignJwtResponseObject, error) {
	if err := signRequest.Body.validate(); err != nil {
		return nil, core.InvalidInputError("invalid sign request: %w", err)
	}
	sig, err := w.C.SignJWT(ctx, signRequest.Body.Claims, signRequest.Body.Kid)
	if err != nil {
		return nil, err
	}
	return SignJwt200TextResponse(sig), nil
}

// SignJws handles api calls for signing a JWS
func (w *Wrapper) SignJws(ctx context.Context, request SignJwsRequestObject) (SignJwsResponseObject, error) {
	signRequest := request.Body
	if err := signRequest.validate(); err != nil {
		return nil, core.InvalidInputError("invalid sign request: %w", err)
	}
	detached := false
	if signRequest.Detached != nil {
		detached = *signRequest.Detached
	}

	headers := signRequest.Headers
	headers[jws.KeyIDKey] = signRequest.Kid // could've been set by caller, but make sure it's set correctly
	sig, err := w.C.SignJWS(ctx, signRequest.Payload, headers, signRequest.Kid, detached)
	if err != nil {
		return nil, err
	}

	return SignJws200TextResponse(sig), nil
}
