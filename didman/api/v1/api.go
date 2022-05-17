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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	vdrDoc "github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)
var _ core.RoutableWithSpec = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

func (w Wrapper) Version() int {
	return 1
}

func (w Wrapper) Name() string {
	return didman.ModuleName
}

func (w Wrapper) JsonSpec() ([]byte, error) {
	return rawSpec()
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		did.ErrInvalidDID:                          http.StatusBadRequest,
		types.ErrNotFound:                          http.StatusNotFound,
		types.ErrDIDNotManagedByThisNode:           http.StatusBadRequest,
		types.ErrDeactivated:                       http.StatusConflict,
		types.ErrDuplicateService:                  http.StatusConflict,
		didman.ErrServiceInUse:                     http.StatusConflict,
		vdrDoc.ErrInvalidOptions:                   http.StatusBadRequest,
		types.ErrServiceNotFound:                   http.StatusNotFound,
		types.ErrInvalidServiceQuery{}:             http.StatusBadRequest,
		types.ErrServiceReferenceToDeep:            http.StatusNotAcceptable,
		didman.ErrReferencedServiceNotAnEndpoint{}: http.StatusNotAcceptable,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, w)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, didman.ModuleName)
}

// Routes registers the routes from the open api spec to the echo router.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// AddEndpoint handles calls to add a service. It only checks params and sets the correct return status code.
// didman.AddEndpoint does the heavy lifting.
func (w *Wrapper) AddEndpoint(ctx echo.Context, didStr string) error {
	request := EndpointProperties{}
	if err := ctx.Bind(&request); err != nil {
		return core.InvalidInputError("failed to parse EndpointCreateRequest: %w", err)
	}

	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	if len(strings.TrimSpace(request.Type)) == 0 {
		return core.InvalidInputError("invalid value for type")
	}

	u, err := url.Parse(request.Endpoint)
	if err != nil {
		return core.InvalidInputError("invalid value for endpoint: %w", err)
	}

	endpoint, err := w.Didman.AddEndpoint(*id, request.Type, *u)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, endpoint)
}

// DeleteEndpointsByType handles calls to delete an endpoint. It only checks params and sets the correct return status code.
// didman.DeleteEndpoint does the heavy lifting.
func (w *Wrapper) DeleteEndpointsByType(ctx echo.Context, didStr string, endpointType string) error {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	if len(strings.TrimSpace(endpointType)) == 0 {
		return core.InvalidInputError("invalid endpointType")
	}

	err = w.Didman.DeleteEndpointsByType(*id, endpointType)
	if err != nil {
		return err
	}
	return ctx.NoContent(http.StatusNoContent)
}

// GetCompoundServices handles calls to get a list of compound services for a provided DID string.
// Its checks params, calls Didman and sets http return values.
func (w *Wrapper) GetCompoundServices(ctx echo.Context, didStr string) error {
	id, err := did.ParseDIDURL(didStr)
	if err != nil {
		return err
	}
	services, err := w.Didman.GetCompoundServices(*id)
	if err != nil {
		return err
	}
	// Service may return nil for empty arrays, map to empty array to avoid returning null from the REST API
	if services == nil {
		services = make([]did.Service, 0)
	}
	return ctx.JSON(http.StatusOK, services)
}

// AddCompoundService handles calls to add a compound service.
// A CompoundService consists of a type and a map of name -> serviceEndpoint(Ref).
//
// This method checks the params: valid DID and type format
// Converts the request to an CompoundService
// Calls didman.AddCompoundService, which does the heavy lifting.
// Converts the response of AddCompoundService, which is a did.Service back to a CompoundService
// Sets the http status OK and adds the CompoundService to the response
func (w *Wrapper) AddCompoundService(ctx echo.Context, didStr string) error {
	// Request parsing and checking
	request := CompoundServiceProperties{}
	if err := ctx.Bind(&request); err != nil {
		return core.InvalidInputError("failed to parse %T: %v", request, err)
	}

	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	if len(strings.TrimSpace(request.Type)) == 0 {
		return core.InvalidInputError("invalid value for type")
	}

	// The api accepts a map[string]interface{} which must be converted to a map[string]ssi.URI.
	references := make(map[string]ssi.URI, len(request.ServiceEndpoint))
	for key, value := range request.ServiceEndpoint {
		uri, err := interfaceToURI(value)
		if err != nil {
			return core.InvalidInputError("invalid reference for service '%s': %v", key, err)
		}
		references[key] = *uri
	}

	// Call Didman
	service, err := w.Didman.AddCompoundService(*id, request.Type, references)
	if err != nil {
		return err
	}

	endpointRefs := map[string]interface{}{}
	serviceEndpoints, ok := service.ServiceEndpoint.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to convert service endpoints")
	}
	for k, v := range serviceEndpoints {
		endpointRefs[k] = v
	}

	cs := CompoundService{
		Id:              service.ID.String(),
		ServiceEndpoint: endpointRefs,
		Type:            service.Type,
	}
	return ctx.JSON(200, cs)
}

// GetCompoundServiceEndpoint handles calls to read a specific endpoint of a compound service.
func (w *Wrapper) GetCompoundServiceEndpoint(ctx echo.Context, didStr string, compoundServiceType string, endpointType string, params GetCompoundServiceEndpointParams) error {
	acceptHeader := ctx.Request().Header.Get("Accept")
	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}
	resolve := true
	if params.Resolve != nil {
		resolve = *params.Resolve
	}
	endpoint, err := w.Didman.GetCompoundServiceEndpoint(*id, compoundServiceType, endpointType, resolve)
	if err != nil {
		return err
	}
	if strings.Contains(acceptHeader, "text/plain") {
		return ctx.String(http.StatusOK, endpoint)
	}

	// default json
	return ctx.JSON(http.StatusOK, EndpointResponse{Endpoint: endpoint})
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
func (w *Wrapper) DeleteService(ctx echo.Context, uriStr string) error {
	id, err := ssi.ParseURI(uriStr)
	if err != nil {
		return core.InvalidInputError("failed to parse URI: %w", err)
	}

	if err = w.Didman.DeleteService(*id); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateContactInformation handles requests for updating contact information for a specific DID.
// It parses the did path param and and unmarshals the request body and passes them to didman.UpdateContactInformation.
func (w *Wrapper) UpdateContactInformation(ctx echo.Context, didStr string) error {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	contactInfo := ContactInformation{}
	if err = ctx.Bind(&contactInfo); err != nil {
		return core.InvalidInputError("failed to parse ContactInformation: %w", err)
	}
	newContactInfo, err := w.Didman.UpdateContactInformation(*id, contactInfo)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, newContactInfo)
}

// GetContactInformation handles requests for contact information for a specific DID.
// It parses the did path param and passes it to didman.GetContactInformation.
func (w *Wrapper) GetContactInformation(ctx echo.Context, didStr string) error {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	contactInfo, err := w.Didman.GetContactInformation(*id)
	if err != nil {
		return err
	}
	if contactInfo == nil {
		return core.NotFoundError("contact information for DID not found")
	}

	return ctx.JSON(http.StatusOK, contactInfo)
}

// SearchOrganizations handles requests for searching organizations, meaning it looks for (valid) Verifiable Credentials
// that map to the "organization" concept and where its subject resolves to an active DID Document.
// It optionally filters only on organizations which DID documents contain a service with the specified type.
func (w *Wrapper) SearchOrganizations(ctx echo.Context, params SearchOrganizationsParams) error {
	results, err := w.Didman.SearchOrganizations(ctx.Request().Context(), params.Query, params.DidServiceType)
	if err != nil {
		return err
	}
	// Service may return nil for empty arrays, map to empty array to avoid returning null from the REST API
	if results == nil {
		results = make([]OrganizationSearchResult, 0)
	}
	return ctx.JSON(http.StatusOK, results)
}
