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

package v1

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/usecase"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
)

var _ StrictServerInterface = Wrapper{}
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

type Wrapper struct {
	Module *usecase.Module
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		usecase.ErrListNotFound:              http.StatusBadRequest,
		usecase.ErrPresentationAlreadyExists: http.StatusBadRequest,
		usecase.ErrMaintainerModeDisabled:    http.StatusBadRequest,
	})
}

func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, usecase.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, usecase.ModuleName, operationID)
		},
	}))
}

func (w Wrapper) GetList(_ context.Context, request GetListRequestObject) (GetListResponseObject, error) {
	var startAfter usecase.Timestamp
	if request.Params.Timestamp != nil && *request.Params.Timestamp > 0 {
		startAfter = usecase.Timestamp(*request.Params.Timestamp)
	}
	presentations, timestamp, err := w.Module.Get(request.ListName, startAfter)
	if err != nil {
		return nil, err
	}
	return GetList200JSONResponse{
		Entries:   presentations,
		Timestamp: int(*timestamp),
	}, nil
}

func (w Wrapper) AddPresentation(_ context.Context, request AddPresentationRequestObject) (AddPresentationResponseObject, error) {
	err := w.Module.Add(request.ListName, *request.Body)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return nil, core.InvalidInputError(err.Error())
		}
		return nil, err
	}
	return AddPresentation201Response{}, nil
}
