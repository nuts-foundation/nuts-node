/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"net/http"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
)

// ResolveVC handles the API request for resolving a VC
func (w *Wrapper) ResolveVC(ctx echo.Context, id string) error {
	vcID, err := ssi.ParseURI(id)
	if err != nil {
		return core.InvalidInputError("invalid credential id: %w", err)
	}
	result, err := w.VCR.Resolve(*vcID, nil)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, *result)
}

// SearchVCs checks the context used in the JSON-LD query, based on the contents it maps to a non-JSON-LD query
func (w *Wrapper) SearchVCs(ctx echo.Context) error {
	var request SearchVCRequest
	err := ctx.Bind(&request)
	if err != nil {
		return core.InvalidInputError("failed to parse request body: %w", err)
	}

	untrusted := false
	if request.SearchOptions != nil && request.SearchOptions.AllowUntrustedIssuer != nil {
		untrusted = *request.SearchOptions.AllowUntrustedIssuer
	}

	if len(request.Query.CredentialSubject) > 1 {
		return core.InvalidInputError("can't match on multiple VC subjects")
	}

	query, err := w.VCR.ExpandAndConvert(request.Query)
	if err != nil {
		return core.InvalidInputError("failed to convert query to JSON-LD expanded form: %w", err)
	}

	results, err := w.VCR.Search(ctx.Request().Context(), query, untrusted, nil)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, results)
}
