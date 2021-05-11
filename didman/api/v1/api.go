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

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const problemTitleAddEndpoint = "Adding Endpoint failed"
const problemTitleDeleteService = "Deleting Service failed"
const problemTitleUpdateContactInformation = "Updating contact information failed"
const problemTitleGetContactInformation = "Getting node's contact information failed"

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

// Routes registers the routes from the open api spec to the echo router.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// AddEndpoint handles calls to add a service. It only checks params and sets the correct return status code.
// didman.AddEndpoint does the heavy lifting.
func (w *Wrapper) AddEndpoint(ctx echo.Context, didStr string) error {
	request := EndpointCreateRequest{}
	if err := ctx.Bind(&request); err != nil {
		err = fmt.Errorf("failed to parse EndpointCreateRequest: %w", err)
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
	}

	id, err := parseDID(didStr, problemTitleAddEndpoint)
	if err != nil {
		return err
	}

	if len(strings.TrimSpace(request.Type)) == 0 {
		err := errors.New("invalid value for type")
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
	}

	u, err := url.Parse(request.Endpoint)
	if err != nil {
		err = fmt.Errorf("invalid value for endpoint: %w", err)
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
	}

	if err = w.Didman.AddEndpoint(*id, request.Type, *u); err != nil {
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, getStatusCode(err), err.Error())
	}

	return ctx.NoContent(http.StatusNoContent)
}

// DeleteService handles calls to delete a service. It only checks params and sets the correct return status code.
// didman.DeleteService does the heavy lifting.
func (w *Wrapper) DeleteService(ctx echo.Context, uriStr string) error {
	id, err := ssi.ParseURI(uriStr)
	if err != nil {
		err = fmt.Errorf("failed to parse URI: %w", err)
		logging.Log().WithError(err).Warn(problemTitleDeleteService)
		return core.NewProblem(problemTitleDeleteService, http.StatusBadRequest, err.Error())
	}

	if err = w.Didman.DeleteService(*id); err != nil {
		logging.Log().WithError(err).Warn(problemTitleDeleteService)
		return core.NewProblem(problemTitleDeleteService, getStatusCode(err), err.Error())
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateContactInformation handles requests for updating contact information for a specific DID.
// It parses the did path param and and unmarshalls the request body and passes them to didman.UpdateContactInformation.
func (w *Wrapper) UpdateContactInformation(ctx echo.Context, didStr string) error {
	id, err := parseDID(didStr, problemTitleUpdateContactInformation)
	if err != nil {
		return err
	}

	contactInfo := ContactInformation{}
	if err = ctx.Bind(&contactInfo); err != nil {
		err = fmt.Errorf("failed to parse ContactInformation: %w", err)
		logging.Log().WithError(err).Warn(problemTitleUpdateContactInformation)
		return core.NewProblem(problemTitleUpdateContactInformation, http.StatusBadRequest, err.Error())
	}
	newContactInfo, err := w.Didman.UpdateContactInformation(*id, contactInfo)
	if err != nil {
		logging.Log().WithError(err).Warn(problemTitleUpdateContactInformation)
		return core.NewProblem(problemTitleUpdateContactInformation, getStatusCode(err), err.Error())
	}

	return ctx.JSON(http.StatusOK, newContactInfo)
}

// GetContactInformation handles requests for contact information for a specific DID.
// It parses the did path param and passes it to didman.GetContactInformation.
func (w *Wrapper) GetContactInformation(ctx echo.Context, didStr string) error {
	id, err := parseDID(didStr, problemTitleGetContactInformation)
	if err != nil {
		return err
	}

	contactInfo, err := w.Didman.GetContactInformation(*id)
	if err != nil {
		logging.Log().WithError(err).Warn(problemTitleGetContactInformation)
		return core.NewProblem(problemTitleGetContactInformation, getStatusCode(err), err.Error())
	}
	if contactInfo == nil {
		return core.NewProblem(problemTitleGetContactInformation, http.StatusNotFound, "contact information for DID not found")
	}

	return ctx.JSON(http.StatusOK, contactInfo)
}

func parseDID(didStr string, problemTitle string) (*did.DID, error) {
	id, err := did.ParseDID(didStr)
	if err != nil {
		err = fmt.Errorf("failed to parse DID: %w", err)
		logging.Log().WithError(err).Warn(problemTitle)
		return nil, core.NewProblem(problemTitle, http.StatusBadRequest, err.Error())
	}
	return id, nil
}

var errorStatusCodes = map[error]int{
	types.ErrNotFound:                http.StatusNotFound,
	types.ErrDIDNotManagedByThisNode: http.StatusBadRequest,
	types.ErrDeactivated:             http.StatusConflict,
	didman.ErrDuplicateService:       http.StatusConflict,
	didman.ErrServiceInUse:           http.StatusConflict,
}

func getStatusCode(err error) int {
	for curr, code := range errorStatusCodes {
		if errors.Is(err, curr) {
			return code
		}
	}
	return http.StatusInternalServerError
}
