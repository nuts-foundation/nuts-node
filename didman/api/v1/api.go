/*
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
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"net/http"
)

// Wrapper implements the ServerInterface.
type Wrapper struct {
	Service *didman.DIDManager
}

func (a *Wrapper) UnapplyServiceTemplate(ctx echo.Context, name string) error {
	panic("implement me")
}

func (a *Wrapper) ApplyServiceTemplate(ctx echo.Context, name string) error {
	request := ServiceTemplateRequest{}
	if err := ctx.Bind(&request); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err.Error()))
	}
	controller, err := did.ParseDID(request.Controller)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("invalid controller: %s", request.Controller))
	}
	subject, err := did.ParseDID(request.Subject)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("invalid subject: %s", request.Subject))
	}
	params := make(map[string]string, 0)
	if request.Params != nil {
		for key, value := range *request.Params {
			valueAsString, valid := value.(string)
			if !valid {
				return ctx.String(http.StatusBadRequest, "invalid input parameters")
			}
			params[key] = valueAsString
		}
	}
	if err := a.Service.ApplyServiceTemplate(*controller, *subject, name, params); err != nil {
		return ctx.String(http.StatusInternalServerError, fmt.Sprintf("service template could not be applied: %s", err.Error()))
	}
	return ctx.NoContent(http.StatusNoContent)
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}
