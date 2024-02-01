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
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"net/http"
	"net/url"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

const requestQueryContextKey = "request.url.query"

type Wrapper struct {
	Server discovery.Server
	Client discovery.Client
}

func (w *Wrapper) ResolveStatusCode(err error) int {
	switch {
	case errors.Is(err, discovery.ErrServerModeDisabled):
		return http.StatusBadRequest
	case errors.Is(err, discovery.ErrInvalidPresentation):
		return http.StatusBadRequest
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
				// deepmap/openapi codegen does not support dynamic query parameters ("exploded form parameters"),
				// so we expose the request URL query parameters to the request context,
				// so the API handler can use them directly.
				newContext := context.WithValue(ctx.Request().Context(), requestQueryContextKey, ctx.Request().URL.Query())
				newRequest := ctx.Request().WithContext(newContext)
				ctx.SetRequest(newRequest)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, discovery.ModuleName, operationID)
		},
	}))
}

func (w *Wrapper) GetPresentations(_ context.Context, request GetPresentationsRequestObject) (GetPresentationsResponseObject, error) {
	var tag *discovery.Tag
	if request.Params.Tag != nil {
		// *string to *Tag
		tag = new(discovery.Tag)
		*tag = discovery.Tag(*request.Params.Tag)
	}
	presentations, newTag, err := w.Server.Get(request.ServiceID, tag)
	if err != nil {
		return nil, err
	}
	return GetPresentations200JSONResponse{
		Entries: presentations,
		Tag:     string(*newTag),
	}, nil
}

func (w *Wrapper) RegisterPresentation(_ context.Context, request RegisterPresentationRequestObject) (RegisterPresentationResponseObject, error) {
	err := w.Server.Register(request.ServiceID, *request.Body)
	if err != nil {
		return nil, err
	}
	return RegisterPresentation201Response{}, nil
}

func (w *Wrapper) SearchPresentations(ctx context.Context, request SearchPresentationsRequestObject) (SearchPresentationsResponseObject, error) {
	// Use query parameters provided in request context (see Routes())
	queryValues := ctx.Value(requestQueryContextKey).(url.Values)
	query := make(map[string]string)
	for key, values := range queryValues {
		query[key] = values[0]
	}
	searchResults, err := w.Client.Search(request.ServiceID, query)
	if err != nil {
		return nil, err
	}
	result := make([]SearchResult, 0)
	for _, searchResult := range searchResults {
		result := SearchResult{
			Vp:     searchResult.Presentation,
			Id:     searchResult.Presentation.ID.String(),
			Fields: searchResult.Fields,
		}
		subjectDID, _ := credential.PresentationSigner(searchResult.Presentation)
		if subjectDID != nil {
			result.SubjectId = subjectDID.String()
		}
		results = append(results, result)
	}
	return SearchPresentations200JSONResponse(results), nil
}

func (w *Wrapper) ActivateServiceForDID(ctx context.Context, request ActivateServiceForDIDRequestObject) (ActivateServiceForDIDResponseObject, error) {
	subjectDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	err = w.Client.ActivateServiceForDID(ctx, request.ServiceID, *subjectDID)
	if errors.Is(err, discovery.ErrPresentationRegistrationFailed) {
		// registration failed, but will be retried
		return ActivateServiceForDID202JSONResponse{
			Reason: err.Error(),
		}, nil
	}
	if err != nil {
		// other error
		return nil, err
	}
	return ActivateServiceForDID200Response{}, nil
}

func (w *Wrapper) DeactivateServiceForDID(ctx context.Context, request DeactivateServiceForDIDRequestObject) (DeactivateServiceForDIDResponseObject, error) {
	subjectDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	err = w.Client.DeactivateServiceForDID(ctx, request.ServiceID, *subjectDID)
	if errors.Is(err, discovery.ErrPresentationRegistrationFailed) {
		// deactivation succeeded, but Verifiable Presentation couldn't be removed from remote Discovery Server.
		return DeactivateServiceForDID202JSONResponse{
			Reason: err.Error(),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return DeactivateServiceForDID200Response{}, nil
}

func (w *Wrapper) GetServices(_ context.Context, _ GetServicesRequestObject) (GetServicesResponseObject, error) {
	result := GetServices200JSONResponse(w.Client.Services())
	return &result, nil
}

func (w *Wrapper) GetServiceActivation(ctx context.Context, request GetServiceActivationRequestObject) (GetServiceActivationResponseObject, error) {
	subjectDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	activated, presentation, err := w.Client.GetServiceActivation(ctx, request.ServiceID, *subjectDID)
	if err != nil {
		return nil, err
	}
	return GetServiceActivation200JSONResponse{
		Activated: activated,
		Vp:        presentation,
	}, nil
}
