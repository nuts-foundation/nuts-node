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
	"errors"
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
		did.ErrInvalidDID:                   http.StatusBadRequest,
		management.ErrInvalidService:        http.StatusBadRequest,
		management.ErrUnsupportedDIDMethod:  http.StatusBadRequest,
		management.ErrDIDAlreadyExists:      http.StatusConflict,
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

func (w *Wrapper) CreateDID(ctx context.Context, request CreateDIDRequestObject) (CreateDIDResponseObject, error) {
	options := management.Create(didweb.MethodName)
	if request.Body.Root != nil && *request.Body.Root {
		options = options.With(didweb.RootDID())
	}

	doc, _, err := w.VDR.Create(ctx, options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return nil, err
	}

	return CreateDID200JSONResponse(*doc), nil
}

func (w *Wrapper) DeleteDID(ctx context.Context, request DeleteDIDRequestObject) (DeleteDIDResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	err = w.VDR.Deactivate(ctx, *targetDID)
	if err != nil {
		return nil, err
	}
	return DeleteDID204Response{}, nil
}

func (w *Wrapper) ResolveDID(_ context.Context, request ResolveDIDRequestObject) (ResolveDIDResponseObject, error) {
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

func (w *Wrapper) ListDIDs(ctx context.Context, _ ListDIDsRequestObject) (ListDIDsResponseObject, error) {
	list, err := w.VDR.DocumentOwner().ListOwned(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(list))
	for i, curr := range list {
		result[i] = curr.String()
	}
	return ListDIDs200JSONResponse(result), nil
}

func (w *Wrapper) CreateService(ctx context.Context, request CreateServiceRequestObject) (CreateServiceResponseObject, error) {
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

func (w *Wrapper) DeleteService(ctx context.Context, request DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
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

func (w *Wrapper) UpdateService(ctx context.Context, request UpdateServiceRequestObject) (UpdateServiceResponseObject, error) {
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

func (w *Wrapper) FilterServices(_ context.Context, request FilterServicesRequestObject) (FilterServicesResponseObject, error) {
	subject, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	didDocument, _, err := w.VDR.Resolve(*subject, nil)
	if err != nil {
		return nil, err
	}

	var results []did.Service
	for _, service := range didDocument.Service {
		if request.Params.Type != nil && *request.Params.Type != service.Type {
			continue
		}
		if request.Params.EndpointType != nil {
			// The value of the serviceEndpoint property MUST be a string, a map, or a set composed of one or more strings and/or maps.
			// All string values MUST be valid URIs conforming to [RFC3986] and normalized according to the Normalization and Comparison rules in RFC3986
			// and to any normalization rules in its applicable URI scheme specification.
			// (taken from https://www.w3.org/TR/did-core/#services)
			var endpointType string
			switch service.ServiceEndpoint.(type) {
			case string:
				endpointType = "string"
			case map[string]interface{}:
				endpointType = "object"
			case []map[string]interface{}:
				endpointType = "array"
			case []interface{}:
				endpointType = "array"
			}
			if string(*request.Params.EndpointType) != endpointType {
				continue
			}
		}
		results = append(results, service)
	}
	return FilterServices200JSONResponse(results), nil
}

func (w Wrapper) AddVerificationMethod(_ context.Context, _ AddVerificationMethodRequestObject) (AddVerificationMethodResponseObject, error) {
	return nil, errors.New("not yet supported")
}

func (w Wrapper) DeleteVerificationMethod(_ context.Context, _ DeleteVerificationMethodRequestObject) (DeleteVerificationMethodResponseObject, error) {
	return nil, errors.New("not yet supported")
}
