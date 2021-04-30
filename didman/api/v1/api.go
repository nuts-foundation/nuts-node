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

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

func (w *Wrapper) AddEndpoint(ctx echo.Context, didStr string) error {
	request := EndpointCreateRequest{}
	if err := ctx.Bind(&request); err != nil {
		err = fmt.Errorf("failed to parse EndpointCreateRequest: %w", err)
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
	}

	id, err := did.ParseDID(didStr)
	if err != nil {
		err = fmt.Errorf("failed to parse DID: %w", err)
		logging.Log().WithError(err).Warn(problemTitleAddEndpoint)
		return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
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
		if errors.Is(err, types.ErrNotFound) {
			return core.NewProblem(problemTitleAddEndpoint, http.StatusNotFound, err.Error())
		}
		if errors.Is(err, types.ErrDIDNotManagedByThisNode) {
			return core.NewProblem(problemTitleAddEndpoint, http.StatusBadRequest, err.Error())
		}
		if errors.Is(err, types.ErrDeactivated) {
			return core.NewProblem(problemTitleAddEndpoint, http.StatusConflict, err.Error())
		}
		if errors.Is(err, didman.ErrDuplicateService) {
			return core.NewProblem(problemTitleAddEndpoint, http.StatusConflict, err.Error())
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (w *Wrapper) DeleteService(ctx echo.Context, uriStr string) error {
	id, err := ssi.ParseURI(uriStr)
	if err != nil {
		err = fmt.Errorf("failed to parse URI: %w", err)
		logging.Log().WithError(err).Warn(problemTitleDeleteService)
		return core.NewProblem(problemTitleDeleteService, http.StatusBadRequest, err.Error())
	}

	if err = w.Didman.DeleteService(*id); err != nil {
		logging.Log().WithError(err).Warn(problemTitleDeleteService)
		if errors.Is(err, types.ErrNotFound) {
			return core.NewProblem(problemTitleDeleteService, http.StatusNotFound, err.Error())
		}
		if errors.Is(err, didman.ErrServiceNotFound) {
			return core.NewProblem(problemTitleDeleteService, http.StatusNotFound, err.Error())
		}
		if errors.Is(err, didman.ErrServiceInUse) {
			return core.NewProblem(problemTitleDeleteService, http.StatusConflict, err.Error())
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}
