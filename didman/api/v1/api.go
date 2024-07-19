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
 *
 */

package v1

import (
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"net/url"
	"strings"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	switch {
	case errors.Is(err, did.ErrInvalidDID):
		return http.StatusBadRequest
	case errors.Is(err, resolver.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, resolver.ErrDIDNotManagedByThisNode):
		return http.StatusBadRequest
	case errors.Is(err, resolver.ErrDeactivated):
		return http.StatusConflict
	case errors.Is(err, resolver.ErrDuplicateService):
		return http.StatusConflict
	case errors.Is(err, didman.ErrServiceInUse):
		return http.StatusConflict
	case errors.Is(err, resolver.ErrServiceNotFound):
		return http.StatusNotFound
	case errors.As(err, new(didnuts.InvalidServiceError)):
		return http.StatusBadRequest
	case errors.As(err, new(resolver.ServiceQueryError)):
		return http.StatusBadRequest
	case errors.Is(err, resolver.ErrServiceReferenceToDeep):
		return http.StatusNotAcceptable
	case errors.As(err, new(didman.ErrReferencedServiceNotAnEndpoint)):
		return http.StatusNotAcceptable
	default:
		return http.StatusInternalServerError
	}
}

// Routes registers the routes from the open api spec to the echo router.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, didman.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, didman.ModuleName, operationID)
		},
	}))
}

func (w *Wrapper) addOrUpdateEndpoint(
	ctx context.Context, requestDID string, properties EndpointProperties,
	operation func(ctx context.Context, id did.DID, serviceType string, endpoint url.URL) (*did.Service, error),
) (*did.Service, error) {
	id, err := did.ParseDID(requestDID)
	if err != nil {
		return nil, err
	}

	if len(strings.TrimSpace(properties.Type)) == 0 {
		return nil, core.InvalidInputError("invalid value for type")
	}

	endpoint, err := url.Parse(properties.Endpoint)
	if err != nil {
		return nil, core.InvalidInputError("invalid value for endpoint: %w", err)
	}
	return operation(ctx, *id, properties.Type, *endpoint)
}

// AddEndpoint handles calls to add a service. It only checks params and sets the correct return status code.
// didman.AddEndpoint does the heavy lifting.
func (w *Wrapper) AddEndpoint(ctx context.Context, request AddEndpointRequestObject) (AddEndpointResponseObject, error) {
	endpoint, err := w.addOrUpdateEndpoint(ctx, request.Did, *request.Body, w.Didman.AddEndpoint)
	if err != nil {
		return nil, err
	}
	return AddEndpoint200JSONResponse(*endpoint), nil
}

// UpdateEndpoint handles calls to update a service. It only checks params and sets the correct return status code.
// didman.UpdateEndpoint does the heavy lifting.
func (w *Wrapper) UpdateEndpoint(ctx context.Context, request UpdateEndpointRequestObject) (UpdateEndpointResponseObject, error) {
	if request.Body.Type != "" && request.Body.Type != request.Type {
		return nil, core.InvalidInputError("updating endpoint type is not supported")
	}
	request.Body.Type = request.Type
	endpoint, err := w.addOrUpdateEndpoint(ctx, request.Did, *request.Body, w.Didman.UpdateEndpoint)
	if err != nil {
		return nil, err
	}
	return UpdateEndpoint200JSONResponse(*endpoint), nil
}

// DeleteEndpointsByType handles calls to delete an endpoint. It only checks params and sets the correct return status code.
// didman.DeleteEndpoint does the heavy lifting.
func (w *Wrapper) DeleteEndpointsByType(ctx context.Context, request DeleteEndpointsByTypeRequestObject) (DeleteEndpointsByTypeResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}

	if len(strings.TrimSpace(request.Type)) == 0 {
		return nil, core.InvalidInputError("invalid endpointType")
	}

	err = w.Didman.DeleteEndpointsByType(ctx, *id, request.Type)
	if err != nil {
		return nil, err
	}
	return DeleteEndpointsByType204Response{}, nil
}

// GetCompoundServices handles calls to get a list of compound services for a provided DID string.
// Its checks params, calls Didman and sets http return values.
func (w *Wrapper) GetCompoundServices(_ context.Context, request GetCompoundServicesRequestObject) (GetCompoundServicesResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	services, err := w.Didman.GetCompoundServices(*id)
	if err != nil {
		return nil, err
	}
	// Service may return nil for empty arrays, map to empty array to avoid returning null from the REST API
	if services == nil {
		services = make([]did.Service, 0)
	}
	r := GetCompoundServices200JSONResponse{}
	for _, service := range services {
		r = append(r, CompoundService(service))
	}
	return r, nil
}

func (w *Wrapper) addOrUpdateCompoundService(
	ctx context.Context, requestDID string, properties CompoundServiceProperties,
	operation func(ctx context.Context, id did.DID, serviceType string, references map[string]ssi.URI) (*did.Service, error),
) (*did.Service, error) {
	id, err := did.ParseDID(requestDID)
	if err != nil {
		return nil, err
	}

	if len(strings.TrimSpace(properties.Type)) == 0 {
		return nil, core.InvalidInputError("invalid value for type")
	}

	// The api accepts a map[string]interface{} which must be converted to a map[string]ssi.URI.
	references := make(map[string]ssi.URI, len(properties.ServiceEndpoint))
	for key, value := range properties.ServiceEndpoint {
		uri, err := interfaceToURI(value)
		if err != nil {
			return nil, core.InvalidInputError("invalid reference for service '%s': %v", key, err)
		}
		references[key] = *uri
	}

	return operation(ctx, *id, properties.Type, references)
}

// AddCompoundService handles calls to add a compound service.
// A CompoundService consists of a type and a map of name -> serviceEndpoint(Ref).
//
// This method checks the params: valid DID and type format
// Converts the request to an CompoundService
// Calls didman.AddCompoundService, which does the heavy lifting.
// Converts the response of AddCompoundService, which is a did.Service back to a CompoundService
// Sets the http status OK and adds the CompoundService to the response
func (w *Wrapper) AddCompoundService(ctx context.Context, request AddCompoundServiceRequestObject) (AddCompoundServiceResponseObject, error) {
	service, err := w.addOrUpdateCompoundService(ctx, request.Did, *request.Body, w.Didman.AddCompoundService)
	if err != nil {
		return nil, err
	}
	return AddCompoundService200JSONResponse(*service), nil
}

// UpdateCompoundService handles calls to update a compound service.
func (w *Wrapper) UpdateCompoundService(ctx context.Context, request UpdateCompoundServiceRequestObject) (UpdateCompoundServiceResponseObject, error) {
	if request.Body.Type != "" && request.Body.Type != request.Type {
		return nil, core.InvalidInputError("updating compound service type is not supported")
	}
	request.Body.Type = request.Type
	service, err := w.addOrUpdateCompoundService(ctx, request.Did, *request.Body, w.Didman.UpdateCompoundService)
	if err != nil {
		return nil, err
	}
	return UpdateCompoundService200JSONResponse(*service), nil
}

// GetCompoundServiceEndpoint handles calls to read a specific endpoint of a compound service.
func (w *Wrapper) GetCompoundServiceEndpoint(_ context.Context, request GetCompoundServiceEndpointRequestObject) (GetCompoundServiceEndpointResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	resolve := true
	if request.Params.Resolve != nil {
		resolve = *request.Params.Resolve
	}
	endpoint, err := w.Didman.GetCompoundServiceEndpoint(*id, request.CompoundServiceType, request.EndpointType, resolve)
	if err != nil {
		return nil, err
	}

	// By default application/json, text/plain if explicitly requested
	var accept string
	if request.Params.Accept != nil {
		accept = *request.Params.Accept
	}
	switch accept {
	case "text/plain":
		return GetCompoundServiceEndpoint200TextResponse(endpoint), nil
	default:
		return GetCompoundServiceEndpoint200JSONResponse{Endpoint: endpoint}, nil
	}
}

func interfaceToURI(input interface{}) (*ssi.URI, error) {
	str, ok := input.(string)
	if !ok {
		return nil, errors.New("not a string")
	}
	return ssi.ParseURI(str)
}

// DeleteService handles calls to delete a service. It only checks params and sets the correct return status code.
// didman.DeleteService does the heavy lifting.
func (w *Wrapper) DeleteService(ctx context.Context, request DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
	id, err := ssi.ParseURI(request.Id)
	if err != nil {
		return nil, core.InvalidInputError("failed to parse URI: %w", err)
	}

	if err = w.Didman.DeleteService(ctx, *id); err != nil {
		return nil, err
	}

	return DeleteService204Response{}, nil
}

// UpdateContactInformation handles requests for updating contact information for a specific DID.
// It parses the did path param and unmarshals the request body and passes them to didman.UpdateContactInformation.
func (w *Wrapper) UpdateContactInformation(ctx context.Context, request UpdateContactInformationRequestObject) (UpdateContactInformationResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	newContactInfo, err := w.Didman.UpdateContactInformation(ctx, *id, *request.Body)
	if err != nil {
		return nil, err
	}

	return UpdateContactInformation200JSONResponse(*newContactInfo), nil
}

// GetContactInformation handles requests for contact information for a specific DID.
// It parses the did path param and passes it to didman.GetContactInformation.
func (w *Wrapper) GetContactInformation(_ context.Context, request GetContactInformationRequestObject) (GetContactInformationResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}

	contactInfo, err := w.Didman.GetContactInformation(*id)
	if err != nil {
		return nil, err
	}
	if contactInfo == nil {
		return nil, core.NotFoundError("contact information for DID not found")
	}

	return GetContactInformation200JSONResponse(*contactInfo), nil
}

// SearchOrganizations handles requests for searching organizations, meaning it looks for (valid) Verifiable Credentials
// that map to the "organization" concept and where its subject resolves to an active DID Document.
// It optionally filters only on organizations which DID documents contain a service with the specified type.
func (w *Wrapper) SearchOrganizations(ctx context.Context, request SearchOrganizationsRequestObject) (SearchOrganizationsResponseObject, error) {
	results, err := w.Didman.SearchOrganizations(ctx, request.Params.Query, request.Params.DidServiceType)
	if err != nil {
		return nil, err
	}
	// Service may return nil for empty arrays, map to empty array to avoid returning null from the REST API
	if results == nil {
		results = make([]OrganizationSearchResult, 0)
	}
	return SearchOrganizations200JSONResponse(results), nil
}
