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
var _ ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		did.ErrInvalidDID:                http.StatusBadRequest,
		types.ErrNotFound:                http.StatusNotFound,
		types.ErrDIDNotManagedByThisNode: http.StatusBadRequest,
		types.ErrDeactivated:             http.StatusConflict,
		types.ErrDuplicateService:        http.StatusConflict,
		didman.ErrServiceInUse:           http.StatusConflict,
		vdrDoc.ErrInvalidOptions:         http.StatusBadRequest,
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
	return ctx.JSON(http.StatusOK, services)
}

// AddCompoundService handles calls to add a compound service. It only checks params and sets the correct return status code.
// didman.AddCompoundService does the heavy lifting.
func (w *Wrapper) AddCompoundService(ctx echo.Context, didStr string) error {
	request := CompoundServiceProperties{}
	if err := ctx.Bind(&request); err != nil {
		return core.InvalidInputError("failed to parse %T: %v", request, err)
	}

	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	references := make(map[string]ssi.URI, 0)
	for key, value := range request.ServiceEndpoint {
		uri, err := interfaceToURI(value)
		if err != nil {
			return core.InvalidInputError("invalid reference for service '%s': %v", key, err)
		}
		references[key] = *uri
	}
	service, err := w.Didman.AddCompoundService(*id, request.Type, references)
	if err != nil {
		return err
	}
	endpointRefs := map[string]interface{}{}
	for k, v := range service.ServiceEndpoint.(map[string]ssi.URI) {
		endpointRefs[k] = v.String()
	}

	cs := CompoundService{
		Id:              service.ID.String(),
		ServiceEndpoint: endpointRefs,
		Type:            service.Type,
	}
	return ctx.JSON(200, cs)
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
