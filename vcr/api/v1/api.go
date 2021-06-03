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
	"net/http"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	R  vcr.VCR
	CR concept.Reader
}

// ErrorStatusCodes maps to errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ErrorStatusCodes() map[error]int {
	return map[error]int{
		concept.ErrUnknownConcept: http.StatusNotFound,
		vcr.ErrNotFound:           http.StatusNotFound,
		vcr.ErrRevoked:            http.StatusConflict,
		credential.ErrValidation:  http.StatusBadRequest,
		types.ErrNotFound:         http.StatusBadRequest,
		types.ErrKeyNotFound:      http.StatusBadRequest,
		vcr.ErrInvalidCredential:  http.StatusNotFound,
	}
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// Search finds concepts. Concepts are mapped to VCs. This is primarily used for finding DIDs.
func (w *Wrapper) Search(ctx echo.Context, conceptTemplate string) error {
	sr := new(SearchRequest)

	if err := ctx.Bind(sr); err != nil {
		return err
	}

	query, err := w.CR.QueryFor(conceptTemplate)
	if err != nil {
		return err
	}

	for _, kvp := range sr.Params {
		query.AddClause(concept.Prefix(kvp.Key, kvp.Value))
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
	idURI, err := ssi.ParseURI(id)

	// return 400 for malformed input
	if err != nil {
		return core.InvalidInputError("failed to parse credential ID: %w", err)
	}

	r, err := w.R.Revoke(*idURI)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, r)
}

// Create a Verifiable credential
func (w *Wrapper) Create(ctx echo.Context) error {
	requestedVC := IssueVCRequest{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	vcCreated, err := w.R.Issue(requestedVC)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// Resolve a VC and return its content
func (w *Wrapper) Resolve(ctx echo.Context, id string) error {
	idURI, err := ssi.ParseURI(id)
	// return 400 for malformed input
	if err != nil {
		return core.InvalidInputError("failed to parse credential ID: %w", err)
	}

	// id is given with fragment
	vc, err := w.R.Resolve(*idURI)
	if vc == nil && err != nil {
		return err
	}

	// transform VC && error
	result := ResolutionResult{
		CurrentStatus:        ResolutionResultCurrentStatusTrusted,
		VerifiableCredential: *vc,
	}

	switch err {
	case vcr.ErrUntrusted:
		result.CurrentStatus = ResolutionResultCurrentStatusUntrusted
	case vcr.ErrRevoked:
		result.CurrentStatus = ResolutionResultCurrentStatusRevoked
	}

	return ctx.JSON(http.StatusOK, result)
}

func (w *Wrapper) TrustIssuer(ctx echo.Context) error {
	return changeTrust(ctx, func(cType ssi.URI, issuer ssi.URI) error {
		return w.R.Trust(cType, issuer)
	})
}

func (w *Wrapper) UntrustIssuer(ctx echo.Context) error {
	return changeTrust(ctx, func(cType ssi.URI, issuer ssi.URI) error {
		return w.R.Untrust(cType, issuer)
	})
}

func (w *Wrapper) ListTrusted(ctx echo.Context, credentialType string) error {
	uri, err := ssi.ParseURI(credentialType)
	if err != nil {
		return core.InvalidInputError("malformed credential type: %w", err)
	}

	trusted, err := w.R.Trusted(*uri)
	if err != nil {
		return err
	}
	result := make([]string, len(trusted))
	for i, t := range trusted {
		result[i] = t.String()
	}

	return ctx.JSON(http.StatusOK, result)
}

func (w *Wrapper) ListUntrusted(ctx echo.Context, credentialType string) error {
	uri, err := ssi.ParseURI(credentialType)
	if err != nil {
		return core.InvalidInputError("malformed credential type: %w", err)
	}

	untrusted, err := w.R.Untrusted(*uri)
	if err != nil {
		return err
	}

	result := make([]string, len(untrusted))
	for i, t := range untrusted {
		result[i] = t.String()
	}

	return ctx.JSON(http.StatusOK, result)
}

type trustChangeFunc func(ssi.URI, ssi.URI) error

func changeTrust(ctx echo.Context, f trustChangeFunc) error {
	var icc = new(CredentialIssuer)

	if err := ctx.Bind(icc); err != nil {
		return err
	}

	d, err := ssi.ParseURI(icc.Issuer)
	if err != nil {
		return core.InvalidInputError("failed to parse issuer: %w", err)
	}

	cType, err := ssi.ParseURI(icc.CredentialType)
	if err != nil {
		return core.InvalidInputError("failed to parse credential type: %w", err)
	}

	if err = f(*cType, *d); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}
