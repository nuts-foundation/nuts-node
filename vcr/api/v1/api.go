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
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	R  vcr.VCR
	CR concept.Registry
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// Search finds concepts. Concepts are mapped to VCs. This is primarily used for finding DIDs.
func (w *Wrapper) Search(ctx echo.Context, ccept string) error {
	////q := params.Query
	//
	//q, err := w.CR.QueryFor(ccept)
	//if err != nil {
	//	ctx.NoContent(http.StatusNotFound)
	//}
	//
	//VCs, err := w.R.Search(q)
	//if err != nil {
	//	return err
	//}
	//
	//var results = make([]concept.Concept, len(VCs))
	//
	//for i, vc := range VCs {
	//	o, err := w.CR.Transform(ccept, vc)
	//	if err != nil {
	//		return err
	//	}
	//
	//	results[i] = o
	//}
	//
	//return ctx.JSON(http.StatusOK, results)
	panic("implement me")
}

// Revoke a credential
func (w *Wrapper) Revoke(ctx echo.Context, id string) error {
	panic("implement me")
}

// Create a Verifiable credential
func (w *Wrapper) Create(ctx echo.Context) error {
	vc := did.VerifiableCredential{}

	if err := ctx.Bind(&vc); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse request body: %s", err.Error()))
	}

	vcCreated, err := w.R.Issue(vc)
	if err != nil {
		if strings.Contains(err.Error(), "validation failed") {
			return ctx.String(http.StatusBadRequest, err.Error())
		}
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// Resolve a VC and return its content
func (w *Wrapper) Resolve(ctx echo.Context, id string) error {
	// id is given with fragment
	vc, err := w.R.Resolve(id)
	if errors.Is(err, vcr.ErrNotFound) {
		return ctx.NoContent(http.StatusNotFound)
	}

	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vc)
}
