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

	"github.com/labstack/echo/v4"
	did2 "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg/model"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR types.VDR
}

func (a Wrapper) CreateDID(ctx echo.Context) error {
	doc, err := a.VDR.Create()
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return err
	}

	// this API returns a DIDDocument according to spec so it may return the business object
	return ctx.JSON(http.StatusOK, *doc)
}

func (a Wrapper) GetDID(ctx echo.Context, did string) error {
	d, err := did2.ParseDID(did)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	// no params in the API for now
	doc, meta, err := a.VDR.Resolve(*d, nil)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return ctx.NoContent(http.StatusNotFound)
		}
		return err
	}

	resolutionResult := DIDResolutionResult{
		Document:         doc,
		DocumentMetadata: meta,
	}

	return ctx.JSON(http.StatusOK, resolutionResult)
}

func (a Wrapper) UpdateDID(ctx echo.Context, did string) error {
	d, err := did2.ParseDID(did)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	req := DIDUpdateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given update request could not be parsed: %s", err.Error()))
	}

	h, err := model.ParseHash(req.CurrentHash)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given hash is not valid: %s", err.Error()))
	}

	if err := a.VDR.Update(*d, h, req.Document, req.DocumentMetadata); err != nil {
		// for middleware maybe
		if errors.Is(err, types.ErrNotFound) {
			return ctx.NoContent(http.StatusNotFound)
		}
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("couldn't update DID document: %s", err.Error()))
	}

	return ctx.JSON(http.StatusOK, req.Document)
}
