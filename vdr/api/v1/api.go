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
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR            vdr.VDR
	DocManipulator management.DocManipulator
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (a *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		resolver.ErrNotFound:                http.StatusNotFound,
		resolver.ErrDIDNotManagedByThisNode: http.StatusForbidden,
		resolver.ErrDeactivated:             http.StatusConflict,
		resolver.ErrNoActiveController:      http.StatusConflict,
		resolver.ErrDuplicateService:        http.StatusBadRequest,
		didnuts.ErrInvalidOptions:           http.StatusBadRequest,
		did.ErrInvalidDID:                   http.StatusBadRequest,
	})
}

// DeleteVerificationMethod accepts a DID and a KeyIdentifier of a verificationMethod and calls the DocManipulator
// to remove the verificationMethod from the given document.
func (a *Wrapper) DeleteVerificationMethod(ctx context.Context, request DeleteVerificationMethodRequestObject) (DeleteVerificationMethodResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}

	kid, err := did.ParseDIDURL(request.Kid)
	if err != nil {
		return nil, core.InvalidInputError("given kid could not be parsed: %w", err)
	}

	err = a.DocManipulator.RemoveVerificationMethod(ctx, *id, *kid)
	if err != nil {
		return nil, fmt.Errorf("could not remove verification method from document: %w", err)
	}
	return DeleteVerificationMethod204Response{}, nil
}

// AddNewVerificationMethod accepts a DID and adds a new VerificationMethod to that corresponding document.
func (a *Wrapper) AddNewVerificationMethod(ctx context.Context, request AddNewVerificationMethodRequestObject) (AddNewVerificationMethodResponseObject, error) {
	d, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}

	opts := request.Body
	if opts == nil {
		opts = &VerificationMethodRelationship{}
	}

	vm, err := a.DocManipulator.AddVerificationMethod(ctx, *d, opts.ToFlags(didnuts.DefaultCreationOptions().KeyFlags))
	if err != nil {
		return nil, err
	}
	return AddNewVerificationMethod200JSONResponse(*vm), nil
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(a, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vdr.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, a)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vdr.ModuleName, operationID)
		},
	}))
}

// CreateDID creates a new DID Document and returns it.
func (a *Wrapper) CreateDID(ctx context.Context, request CreateDIDRequestObject) (CreateDIDResponseObject, error) {
	options := didnuts.DefaultCreationOptions()
	if request.Body.Controllers != nil {
		for _, c := range *request.Body.Controllers {
			id, err := did.ParseDID(c)
			if err != nil {
				return nil, core.InvalidInputError("controller entry (%s) could not be parsed: %w", c, err)
			}
			options.Controllers = append(options.Controllers, *id)
		}
	}
	options.KeyFlags = request.Body.VerificationMethodRelationship.ToFlags(options.KeyFlags)
	if request.Body.SelfControl != nil {
		options.SelfControl = *request.Body.SelfControl
	}

	doc, _, err := a.VDR.Create(ctx, options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return nil, err
	}

	// this API returns a DIDDocument according to spec, so it may return the business object
	return CreateDID200JSONResponse(*doc), nil
}

// GetDID returns a DID document and DID document metadata based on a DID.
func (a *Wrapper) GetDID(ctx context.Context, request GetDIDRequestObject) (GetDIDResponseObject, error) {
	d, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.InvalidInputError("given did is not valid: %w", err)
	}
	resolverMetadata := &resolver.ResolveMetadata{AllowDeactivated: true}

	params := request.Params
	if params.VersionId != nil {
		if params.VersionTime != nil {
			return nil, core.InvalidInputError("versionId and versionTime are mutually exclusive")
		}
		versionHash, err := hash.ParseHex(*params.VersionId)
		if err != nil {
			return nil, core.InvalidInputError("given hash is not valid: %w", err)
		}
		resolverMetadata.Hash = &versionHash
	}

	if params.VersionTime != nil {
		versionTime, err := time.Parse(time.RFC3339, *params.VersionTime)
		if err != nil {
			return nil, core.InvalidInputError("versionTime has invalid format: %w", err)
		}
		resolverMetadata.ResolveTime = &versionTime
	}

	doc, meta, err := a.VDR.Resolver().Resolve(*d, resolverMetadata)
	if err != nil {
		return nil, err
	}

	resolutionResult := DIDResolutionResult{
		Document:         *doc,
		DocumentMetadata: *meta,
	}

	return GetDID200JSONResponse(resolutionResult), nil
}

func (a *Wrapper) ConflictedDIDs(_ context.Context, _ ConflictedDIDsRequestObject) (ConflictedDIDsResponseObject, error) {
	docs, metas, err := a.VDR.ConflictedDocuments()
	if err != nil {
		// 500 internal server error
		return nil, err
	}

	// []docs, []meta to [](doc, meta)
	returnValues := make([]DIDResolutionResult, len(docs))
	for i := range docs {
		returnValues[i] = DIDResolutionResult{
			Document:         docs[i],
			DocumentMetadata: metas[i],
		}
	}

	return ConflictedDIDs200JSONResponse(returnValues), nil
}

// UpdateDID updates a DID Document given a DID and DID Document body. It returns the updated DID Document.
func (a *Wrapper) UpdateDID(ctx context.Context, request UpdateDIDRequestObject) (UpdateDIDResponseObject, error) {
	d, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}

	err = a.VDR.Update(ctx, *d, request.Body.Document)
	if err != nil {
		return nil, err
	}
	return UpdateDID200JSONResponse(request.Body.Document), nil
}

// DeactivateDID deactivates a DID Document given a DID.
// It returns a 200 and an empty body if the deactivation was successful.
func (a *Wrapper) DeactivateDID(ctx context.Context, request DeactivateDIDRequestObject) (DeactivateDIDResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	err = a.DocManipulator.Deactivate(ctx, *id)
	if err != nil {
		return nil, err
	}
	return &DeactivateDID200Response{}, nil
}
