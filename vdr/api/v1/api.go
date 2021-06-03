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
	"fmt"
	"net/http"

	"github.com/nuts-foundation/go-did/did"
	vdrDoc "github.com/nuts-foundation/nuts-node/vdr/doc"

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

func (a *Wrapper) ErrorStatusCodes() map[error]int {
	return map[error]int{
		types.ErrNotFound:                http.StatusNotFound,
		types.ErrDIDNotManagedByThisNode: http.StatusForbidden,
		types.ErrDeactivated:             http.StatusConflict,
		vdrDoc.ErrInvalidOptions:         http.StatusBadRequest,
		did.ErrInvalidDID:                http.StatusBadRequest,
	}
}

// DeleteVerificationMethod accepts a DID and a KeyIdentifier of a verificationMethod and calls the DocManipulator
// to remove the verificationMethod from the given document.
func (a *Wrapper) DeleteVerificationMethod(ctx echo.Context, didStr string, kidStr string) error {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return err
	}

	kid, err := did.ParseDIDURL(kidStr)
	if err != nil {
		return core.InvalidInputError("given kid could not be parsed: %w", err)
	}

	err = a.DocManipulator.RemoveVerificationMethod(*id, *kid)
	if err != nil {
		return fmt.Errorf("could not remove verification method from document: %w", err)
	}
	return ctx.NoContent(http.StatusNoContent)
}

// AddNewVerificationMethod accepts a DID and adds a new VerificationMethod to that corresponding document.
func (a *Wrapper) AddNewVerificationMethod(ctx echo.Context, id string) error {
	d, err := did.ParseDID(id)
	if err != nil {
		return err
	}

	vm, err := a.DocManipulator.AddVerificationMethod(*d)
	if err != nil {
		return err
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
		return err
	}

	options := vdrDoc.DefaultCreationOptions()
	if req.Controllers != nil {
		for _, c := range *req.Controllers {
			id, err := did.ParseDID(c)
			if err != nil {
				return core.InvalidInputError("controller entry (%s) could not be parsed: %w", c, err)
			}
			options.Controllers = append(options.Controllers, *id)
		}
	}

	if req.Authentication != nil {
		options.Authentication = *req.Authentication
	}
	if req.AssertionMethod != nil {
		options.AssertionMethod = *req.AssertionMethod
	}
	if req.CapabilityDelegation != nil {
		options.CapabilityDelegation = *req.CapabilityDelegation
	}
	if req.CapabilityInvocation != nil {
		options.CapabilityInvocation = *req.CapabilityInvocation
	}
	if req.KeyAgreement != nil && *req.KeyAgreement {
		options.KeyAgreement = *req.KeyAgreement
	}
	if req.SelfControl != nil {
		options.SelfControl = *req.SelfControl
	}

	doc, _, err := a.VDR.Create(options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return err
	}

	// this API returns a DIDDocument according to spec so it may return the business object
	return ctx.JSON(http.StatusOK, *doc)
}

// GetDID returns a DID document and DID document metadata based on a DID.
func (a Wrapper) GetDID(ctx echo.Context, targetDID string) error {
	d, err := did.ParseDID(targetDID)
	if err != nil {
		return err
	}

	// no params in the API for now
	doc, meta, err := a.DocResolver.Resolve(*d, nil)
	if err != nil {
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
		return err
	}

	req := DIDUpdateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	h, err := hash.ParseHex(req.CurrentHash)
	if err != nil {
		return core.InvalidInputError("given hash is not valid: %w", err)
	}

	err = a.VDR.Update(*d, h, req.Document, nil)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, req.Document)
}

// DeactivateDID deactivates a DID Document given a DID.
// It returns a 200 and an empty body if the deactivation was successful.
func (a *Wrapper) DeactivateDID(ctx echo.Context, targetDID string) error {
	id, err := did.ParseDID(targetDID)
	if err != nil {
		return err
	}
	err = a.DocManipulator.Deactivate(*id)
	if err != nil {
		return err
	}
	return ctx.NoContent(http.StatusOK)
}
