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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"net/http"
	"net/url"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

type requestQueryContextKey struct{}

type Wrapper struct {
	Client discovery.Client
}

func (w *Wrapper) ResolveStatusCode(err error) int {
	switch {
	case errors.Is(err, discovery.ErrServiceNotFound):return http.StatusNotFound
	case errors.Is(err, didsubject.ErrSubjectNotFound):return http.StatusNotFound
	case errors.Is(err, discovery.ErrPresentationRegistrationFailed):return http.StatusPreconditionFailed
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
				newContext := context.WithValue(ctx.Request().Context(), requestQueryContextKey{}, ctx.Request().URL.Query())
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

func (w *Wrapper) SearchPresentations(ctx context.Context, request SearchPresentationsRequestObject) (SearchPresentationsResponseObject, error) {
	// Use query parameters provided in request context (see Routes())
	queryValues := ctx.Value(requestQueryContextKey{}).(url.Values)
	query := make(map[string]string)
	for path, values := range queryValues {
		query[path] = values[0]
	}
	searchResults, err := w.Client.Search(request.ServiceID, query)
	if err != nil {
		return nil, err
	}
	results := make([]SearchResult, 0)
	for _, searchResult := range searchResults {
		result := SearchResult{
			Vp:                     searchResult.Presentation,
			Id:                     searchResult.Presentation.ID.String(),
			Fields:                 searchResult.Fields,
			RegistrationParameters: searchResult.Parameters,
		}
		subjectDID, _ := credential.PresentationSigner(searchResult.Presentation)
		if subjectDID != nil {
			result.CredentialSubjectId = subjectDID.String()
		}
		results = append(results, result)
	}
	return SearchPresentations200JSONResponse(results), nil
}

func (w *Wrapper) ActivateServiceForSubject(ctx context.Context, request ActivateServiceForSubjectRequestObject) (ActivateServiceForSubjectResponseObject, error) {
	var parameters map[string]interface{}
	if request.Body != nil && request.Body.RegistrationParameters != nil {
		parameters = *request.Body.RegistrationParameters
	}

	err := w.Client.ActivateServiceForSubject(ctx, request.ServiceID, request.SubjectID, parameters)
	if err != nil {
		// other error
		return nil, err
	}
	return ActivateServiceForSubject200Response{}, nil
}

func (w *Wrapper) DeactivateServiceForSubject(ctx context.Context, request DeactivateServiceForSubjectRequestObject) (DeactivateServiceForSubjectResponseObject, error) {
	err := w.Client.DeactivateServiceForSubject(ctx, request.ServiceID, request.SubjectID)
	if err != nil {
		return nil, err
	}
	return DeactivateServiceForSubject200Response{}, nil
}

func (w *Wrapper) GetServices(_ context.Context, _ GetServicesRequestObject) (GetServicesResponseObject, error) {
	result := GetServices200JSONResponse(w.Client.Services())
	return &result, nil
}

func (w *Wrapper) GetServiceActivation(ctx context.Context, request GetServiceActivationRequestObject) (GetServiceActivationResponseObject, error) {
	activated, presentations, err := w.Client.GetServiceActivation(ctx, request.ServiceID, request.SubjectID)
	if err != nil {
		return nil, err
	}
	return GetServiceActivation200JSONResponse{
		Activated: activated,
		Vp:        &presentations,
	}, nil
}
