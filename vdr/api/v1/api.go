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
	"time"

	httpModule "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vdr"

	"github.com/nuts-foundation/go-did/did"
	vdrDoc "github.com/nuts-foundation/nuts-node/vdr/didservice"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR            types.VDR
	DocManipulator types.DocManipulator
	DocResolver    types.DocResolver
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (a *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		types.ErrNotFound:                http.StatusNotFound,
		types.ErrDIDNotManagedByThisNode: http.StatusForbidden,
		types.ErrDeactivated:             http.StatusConflict,
		types.ErrNoActiveController:      http.StatusConflict,
		types.ErrDuplicateService:        http.StatusBadRequest,
		vdrDoc.ErrInvalidOptions:         http.StatusBadRequest,
		did.ErrInvalidDID:                http.StatusBadRequest,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (a *Wrapper) Preprocess(operationID string, context echo.Context) {
	httpModule.Preprocess(context, a, vdr.ModuleName, operationID)
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

	err = a.DocManipulator.RemoveVerificationMethod(ctx.Request().Context(), *id, *kid)
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
	req := AddNewVerificationMethodJSONRequestBody{}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	vm, err := a.DocManipulator.AddVerificationMethod(ctx.Request().Context(), *d, req.ToFlags(vdrDoc.DefaultCreationOptions().KeyFlags))
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, *vm)
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}

// CreateDID creates a new DID Document and returns it.
func (a *Wrapper) CreateDID(ctx echo.Context) error {
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
	options.KeyFlags = req.VerificationMethodRelationship.ToFlags(options.KeyFlags)
	if req.SelfControl != nil {
		options.SelfControl = *req.SelfControl
	}

	doc, _, err := a.VDR.Create(ctx.Request().Context(), options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return err
	}

	// this API returns a DIDDocument according to spec, so it may return the business object
	return ctx.JSON(http.StatusOK, *doc)
}

// GetDID returns a DID document and DID document metadata based on a DID.
func (a *Wrapper) GetDID(ctx echo.Context, targetDID string, params GetDIDParams) error {
	d, err := did.ParseDID(targetDID)
	if err != nil {
		return core.InvalidInputError("given did is not valid: %w", err)
	}
	resolverMetadata := &types.ResolveMetadata{AllowDeactivated: true}

	if params.VersionId != nil {
		if params.VersionTime != nil {
			return core.InvalidInputError("versionId and versionTime are mutually exclusive")
		}
		versionHash, err := hash.ParseHex(*params.VersionId)
		if err != nil {
			return core.InvalidInputError("given hash is not valid: %w", err)
		}
		resolverMetadata.Hash = &versionHash
	}

	if params.VersionTime != nil {
		versionTime, err := time.Parse(time.RFC3339, *params.VersionTime)
		if err != nil {
			return core.InvalidInputError("versionTime has invalid format: %w", err)
		}
		resolverMetadata.ResolveTime = &versionTime
	}

	doc, meta, err := a.DocResolver.Resolve(*d, resolverMetadata)
	if err != nil {
		return err
	}

	resolutionResult := DIDResolutionResult{
		Document:         *doc,
		DocumentMetadata: *meta,
	}

	return ctx.JSON(http.StatusOK, resolutionResult)
}

func (a *Wrapper) ConflictedDIDs(ctx echo.Context) error {
	docs, metas, err := a.VDR.ConflictedDocuments()
	if err != nil {
		// 500 internal server error
		return err
	}

	// []docs, []meta to [](doc, meta)
	returnValues := make([]DIDResolutionResult, len(docs))
	for i := range docs {
		returnValues[i] = DIDResolutionResult{
			Document:         docs[i],
			DocumentMetadata: metas[i],
		}
	}

	return ctx.JSON(http.StatusOK, returnValues)
}

// UpdateDID updates a DID Document given a DID and DID Document body. It returns the updated DID Document.
func (a *Wrapper) UpdateDID(ctx echo.Context, targetDID string) error {
	d, err := did.ParseDID(targetDID)
	if err != nil {
		return err
	}

	req := DIDUpdateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	err = a.VDR.Update(ctx.Request().Context(), *d, req.Document)
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
	err = a.DocManipulator.Deactivate(ctx.Request().Context(), *id)
	if err != nil {
		return err
	}
	return ctx.NoContent(http.StatusOK)
}
