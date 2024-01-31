/*
 * Nuts node
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

package v2

import (
	"context"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR vdr.VDR
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		resolver.ErrNotFound:                http.StatusNotFound,
		resolver.ErrDIDNotManagedByThisNode: http.StatusForbidden,
		resolver.ErrDuplicateService:        http.StatusBadRequest,
		did.ErrInvalidDID:                   http.StatusBadRequest,
	})
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vdr.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vdr.ModuleName, operationID)
		},
	}))
}

func (w Wrapper) CreateDID(ctx context.Context, request CreateDIDRequestObject) (CreateDIDResponseObject, error) {
	options := management.Create(didweb.MethodName)
	if request.Body.Id != nil && *request.Body.Id != "" {
		options = options.With(didweb.UserPath(*request.Body.Id))
	}

	doc, _, err := w.VDR.Create(ctx, options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return nil, err
	}

	return CreateDID200JSONResponse(*doc), nil
}

func (w Wrapper) DeleteDID(ctx context.Context, request DeleteDIDRequestObject) (DeleteDIDResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) ResolveDID(_ context.Context, request ResolveDIDRequestObject) (ResolveDIDResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	didDocument, metadata, err := w.VDR.Resolve(*targetDID, nil)
	if err != nil {
		return nil, err
	}
	return ResolveDID200JSONResponse{
		Document:         *didDocument,
		DocumentMetadata: *metadata,
	}, nil
}

func (a *Wrapper) ListDIDs(ctx context.Context, _ ListDIDsRequestObject) (ListDIDsResponseObject, error) {
	list, err := a.VDR.ListOwned(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(list))
	for i, curr := range list {
		result[i] = curr.String()
	}
	return ListDIDs200JSONResponse(result), nil
}

func (w Wrapper) CreateService(ctx context.Context, request CreateServiceRequestObject) (CreateServiceResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	createdService, err := w.VDR.CreateService(ctx, *targetDID, *request.Body)
	if err != nil {
		return nil, err
	}
	return CreateService200JSONResponse(*createdService), nil
}

func (w Wrapper) DeleteService(ctx context.Context, request DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	serviceID, err := ssi.ParseURI(request.ServiceId)
	if err != nil {
		return nil, err
	}
	err = w.VDR.DeleteService(ctx, *targetDID, *serviceID)
	if err != nil {
		return nil, err
	}
	return DeleteService204Response{}, nil
}

func (w Wrapper) UpdateService(ctx context.Context, request UpdateServiceRequestObject) (UpdateServiceResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	serviceID, err := ssi.ParseURI(request.ServiceId)
	if err != nil {
		return nil, err
	}
	newService, err := w.VDR.UpdateService(ctx, *targetDID, *serviceID, *request.Body)
	if err != nil {
		return nil, err
	}
	return UpdateService200JSONResponse(*newService), nil
}

func (w Wrapper) AddVerificationMethod(ctx context.Context, request AddVerificationMethodRequestObject) (AddVerificationMethodResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) DeleteVerificationMethod(ctx context.Context, request DeleteVerificationMethodRequestObject) (DeleteVerificationMethodResponseObject, error) {
	//TODO implement me
	panic("implement me")
}
