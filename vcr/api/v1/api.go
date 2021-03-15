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
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
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
func (w *Wrapper) Search(ctx echo.Context, conceptTemplate string) error {
	sr := new(SearchRequest)

	if err := ctx.Bind(sr); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse request body: %s", err.Error()))
	}

	query, err := w.CR.QueryFor(conceptTemplate)
	if err != nil {
		if err == concept.ErrUnknownConcept {
			return ctx.NoContent(http.StatusNotFound)
		}
		return err
	}

	for _, kvp := range sr.Params {
		query.AddClause(concept.Eq(kvp.Key, kvp.Value))
	}

	VCs, err := w.R.Search(query)
	if err != nil {
		return err
	}

	var results = make([]concept.Concept, len(VCs))

	for i, vc := range VCs {
		o, err := w.CR.Transform(conceptTemplate, vc)
		if err != nil {
			return err
		}

		results[i] = o
	}

	return ctx.JSON(http.StatusOK, results)
}

// Revoke a credential
func (w *Wrapper) Revoke(ctx echo.Context, id string) error {
	idURI, err := did.ParseURI(id)

	// return 400 for malformed input
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse credential ID: %s", err.Error()))
	}

	r, err := w.R.Revoke(*idURI)
	// 404 not found
	if errors.Is(err, vcr.ErrNotFound) {
		return ctx.NoContent(http.StatusNotFound)
	}

	// return 409 when already revoked
	if errors.Is(err, vcr.ErrRevoked) {
		return ctx.NoContent(http.StatusConflict)
	}

	// 400 not the issuer
	if errors.Is(err, vcr.ErrInvalidIssuer) {
		return ctx.String(http.StatusBadRequest, "no issuer private key found")
	}

	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, r)
}

// Create a Verifiable credential
func (w *Wrapper) Create(ctx echo.Context) error {
	vc := did.VerifiableCredential{}

	if err := ctx.Bind(&vc); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse request body: %s", err.Error()))
	}

	vcCreated, err := w.R.Issue(vc)
	if err != nil {
		if errors.Is(err, credential.ErrValidation) {
			return ctx.String(http.StatusBadRequest, err.Error())
		}
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// Resolve a VC and return its content
func (w *Wrapper) Resolve(ctx echo.Context, id string) error {
	idURI, err := did.ParseURI(id)
	// return 400 for malformed input
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse credential ID: %s", err.Error()))
	}

	// id is given with fragment
	vc, err := w.R.Resolve(*idURI)
	if errors.Is(err, vcr.ErrNotFound) {
		return ctx.NoContent(http.StatusNotFound)
	}

	// 500
	if vc == nil && err != nil {
		return err
	}

	// transform VC && error
	rr := ResolutionResult{
		CurrentStatus:        trusted,
		VerifiableCredential: *vc,
	}

	switch err {
	case vcr.ErrUntrusted:
		rr.CurrentStatus = untrusted
	case vcr.ErrRevoked:
		rr.CurrentStatus = revoked
	}

	return ctx.JSON(http.StatusOK, rr)
}

func (w *Wrapper) RemoveTrust(ctx echo.Context) error {
	return changeTrust(ctx, func(cType did.URI, d did.URI) error {
		return w.R.RemoveTrust(cType, d)
	})
}

func (w *Wrapper) AddTrust(ctx echo.Context) error {
	return changeTrust(ctx, func(cType did.URI, d did.URI) error {
		return w.R.AddTrust(cType, d)
	})
}

type trustChangeFunc func(did.URI, did.URI) error

func changeTrust(ctx echo.Context, f trustChangeFunc) error {
	var icc = new(IssuerCredentialCombination)

	if err := ctx.Bind(icc); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse request body: %s", err.Error()))
	}

	d, err := did.ParseURI(icc.Issuer)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse issuer: %s", err.Error()))
	}

	cType, err := did.ParseURI(icc.CredentialType)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("failed to parse credential type: %s", err.Error()))
	}

	if err = f(*cType, *d); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusAccepted)
}
