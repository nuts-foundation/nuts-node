/*
 * Copyright (C) 2024 Nuts community
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

package server

import (
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/nuts-foundation/nuts-node/discovery/api/server/client"
	"net/http"
)

type VerifiablePresentation = vc.VerifiablePresentation
type PresentationsResponse = client.PresentationsResponse

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

type Wrapper struct {
	Server discovery.Server
}

func (w *Wrapper) ResolveStatusCode(err error) int {
	switch {
	case errors.Is(err, discovery.ErrInvalidPresentation):
		return http.StatusBadRequest
	case errors.Is(err, discovery.ErrDIDMethodsNotSupported):
		return http.StatusBadRequest
	case errors.Is(err, discovery.ErrServiceNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, discovery.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
	}))
}

func (w *Wrapper) GetPresentations(ctx context.Context, request GetPresentationsRequestObject) (GetPresentationsResponseObject, error) {
	var timestamp int
	if request.Params.Timestamp != nil {
		timestamp = *request.Params.Timestamp
	}

	presentations, newTimestamp, err := w.Server.Get(contextWithForwardedHost(ctx), request.ServiceID, timestamp)
	if err != nil {
		return nil, err
	}
	return GetPresentations200JSONResponse{
		Entries:   presentations,
		Timestamp: newTimestamp,
	}, nil
}

func (w *Wrapper) RegisterPresentation(ctx context.Context, request RegisterPresentationRequestObject) (RegisterPresentationResponseObject, error) {
	err := w.Server.Register(contextWithForwardedHost(ctx), request.ServiceID, *request.Body)
	if err != nil {
		return nil, err
	}
	return RegisterPresentation201Response{}, nil
}

func contextWithForwardedHost(ctx context.Context) context.Context {
	// cast context to echo.Context
	echoCtx := ctx.Value("echo.Context")
	if echoCtx != nil {
		// forward X-Forwarded-Host header via context
		ctx = context.WithValue(ctx, discovery.XForwardedHostContextKey{}, echoCtx.(echo.Context).Request().Header.Get("X-Forwarded-Host"))
	}
	return ctx
}
