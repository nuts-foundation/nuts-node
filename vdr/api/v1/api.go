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

	"github.com/nuts-foundation/go-did/did"
	doc2 "github.com/nuts-foundation/nuts-node/vdr/doc"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR            types.VDR
	DocManipulator types.DocManipulator
	DocResolver    types.DocResolver
}

// DeleteVerificationMethod accepts a DID and a KeyIdentifier of a verificationMethod and calls the DocManipulator
// to remove the verificationMethod from the given document.
func (a *Wrapper) DeleteVerificationMethod(ctx echo.Context, didStr string, kidStr string) error {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	kid, err := did.ParseDID(kidStr)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given kid could not be parsed: %s", err.Error()))
	}

	err = a.DocManipulator.RemoveVerificationMethod(*id, *kid)
	if err != nil {
		return handleError(ctx, err, "could not remove verification method from document: %s")
	}
	return ctx.NoContent(http.StatusNoContent)
}

// AddNewVerificationMethod accepts a DID and adds a new VerificationMethod to that corresponding document.
func (a *Wrapper) AddNewVerificationMethod(ctx echo.Context, id string) error {
	d, err := did.ParseDID(id)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	vm, err := a.DocManipulator.AddVerificationMethod(*d)
	if err != nil {
		return handleError(ctx, err, "could not update DID document: %s")
	}
	return ctx.JSON(http.StatusOK, *vm)
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}

// CreateDID creates a new DID Document and returns it.
func (a Wrapper) CreateDID(ctx echo.Context) error {
	req := DIDCreateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("create request could not be parsed: %s", err.Error()))
	}

	options := doc2.DefaultCreationOptions()
	if req.Controllers != nil {
		for _, c := range *req.Controllers {
			id, err := did.ParseDID(c)
			if err != nil {
				return ctx.String(http.StatusBadRequest, fmt.Sprintf("controller entry (%s) could not be parsed: %s", c, err.Error()))
			}
			options.Controllers = append(options.Controllers, *id)
		}
	}

	if req.Authentication != nil && *req.Authentication {
		options.Authentication = true
	}
	if req.AssertionMethod != nil && !*req.AssertionMethod {
		options.Authentication = false
	}
	if req.CapablilityDelegation != nil && *req.CapablilityDelegation {
		options.CapabilityDelegation = true
	}
	if req.CapablilityInvocation != nil && !*req.CapablilityInvocation {
		options.CapabilityInvocation = false
	}
	if req.KeyAgreement != nil && !*req.KeyAgreement {
		options.KeyAgreement = false
	}
	if req.SelfControl != nil && !*req.SelfControl {
		options.SelfControl = false
	}

	doc, _, err := a.VDR.Create(options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		if errors.Is(err, doc2.ErrInvalidOptions) {
			return ctx.String(http.StatusBadRequest, err.Error())
		}
		return err
	}

	// this API returns a DIDDocument according to spec so it may return the business object
	return ctx.JSON(http.StatusOK, *doc)
}

// GetDID returns a DID document and DID document metadata based on a DID.
func (a Wrapper) GetDID(ctx echo.Context, targetDID string) error {
	d, err := did.ParseDID(targetDID)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	// no params in the API for now
	doc, meta, err := a.DocResolver.Resolve(*d, nil)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return ctx.String(http.StatusNotFound, "DID document not found")
		}
		return err
	}

	resolutionResult := DIDResolutionResult{
		Document:         *doc,
		DocumentMetadata: *meta,
	}

	return ctx.JSON(http.StatusOK, resolutionResult)
}

// UpdateDID updates a DID Document given a DID and DID Document body. It returns the updated DID Document.
func (a Wrapper) UpdateDID(ctx echo.Context, targetDID string) error {
	d, err := did.ParseDID(targetDID)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}

	req := DIDUpdateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given update request could not be parsed: %s", err.Error()))
	}

	h, err := hash.ParseHex(req.CurrentHash)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given hash is not valid: %s", err.Error()))
	}

	err = a.VDR.Update(*d, h, req.Document, nil)
	if err != nil {
		return handleError(ctx, err, "could not update DID document: %s")
	}
	return ctx.JSON(http.StatusOK, req.Document)
}

// DeactivateDID deactivates a DID Document given a DID.
// It returns a 200 and an empty body if the deactivation was successful.
func (a *Wrapper) DeactivateDID(ctx echo.Context, targetDID string) error {
	id, err := did.ParseDID(targetDID)
	if err != nil {
		return ctx.String(http.StatusBadRequest, fmt.Sprintf("given DID could not be parsed: %s", err.Error()))
	}
	err = a.DocManipulator.Deactivate(*id)
	if err != nil {
		return handleError(ctx, err, "could not deactivate DID document: %s")
	}
	return ctx.NoContent(http.StatusOK)
}

// handleError make error handling consistent. It accepts the echo context an error and a template.
// Based on the error the correct status code gets selected
// The error message is put in the %s location of the errTemplate
func handleError(ctx echo.Context, err error, errTemplate string) error {
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return ctx.String(http.StatusNotFound, fmt.Sprintf(errTemplate, err.Error()))
		}
		if errors.Is(err, types.ErrDIDNotManagedByThisNode) {
			return ctx.String(http.StatusForbidden, fmt.Sprintf(errTemplate, err.Error()))
		}
		if errors.Is(err, types.ErrDeactivated) {
			return ctx.String(http.StatusConflict, fmt.Sprintf(errTemplate, err.Error()))
		}
		return ctx.String(http.StatusInternalServerError, fmt.Sprintf(errTemplate, err.Error()))
	}
	return err
}
