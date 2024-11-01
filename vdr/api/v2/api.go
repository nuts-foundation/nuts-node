/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
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
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/http/cache"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"time"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// cacheControlMaxAgeURLs holds API endpoints that should have a max-age cache control header set.
var cacheControlMaxAgeURLs = []string{
	"/.well-known/did.json",
	"/iam/:id/did.json",
}

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR            vdr.VDR
	SubjectManager didsubject.Manager
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		didsubject.ErrSubjectNotFound:          http.StatusNotFound,
		didsubject.ErrSubjectAlreadyExists:     http.StatusConflict,
		resolver.ErrNotFound:                   http.StatusNotFound,
		resolver.ErrDIDNotManagedByThisNode:    http.StatusForbidden,
		did.ErrInvalidDID:                      http.StatusBadRequest,
		didsubject.ErrInvalidService:           http.StatusBadRequest,
		didsubject.ErrUnsupportedDIDMethod:     http.StatusBadRequest,
		didsubject.ErrKeyAgreementNotSupported: http.StatusBadRequest,
		didsubject.ErrSubjectValidation:        http.StatusBadRequest,
		resolver.ErrDeactivated:                http.StatusConflict,
		did.ErrInvalidService:                  http.StatusBadRequest,
		resolver.ErrDuplicateService:           http.StatusConflict,
	})
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vdr.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vdr.ModuleName, operationID)
		},
	}))
	router.Use(cache.MaxAge(5*time.Minute, cacheControlMaxAgeURLs...).Handle)
}

func (r Wrapper) GetTenantWebDID(_ context.Context, request GetTenantWebDIDRequestObject) (GetTenantWebDIDResponseObject, error) {
	ownDID := r.requestedWebDID(request.Id)
	document, err := r.VDR.ResolveManaged(ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetTenantWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve tenant did:web: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetTenantWebDID200JSONResponse(*document), nil
}

func (r Wrapper) GetRootWebDID(ctx context.Context, _ GetRootWebDIDRequestObject) (GetRootWebDIDResponseObject, error) {
	ownDID := r.requestedWebDID("")
	document, err := r.VDR.ResolveManaged(ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetRootWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve root did:web: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetRootWebDID200JSONResponse(*document), nil
}

func (w *Wrapper) CreateSubject(ctx context.Context, request CreateSubjectRequestObject) (CreateSubjectResponseObject, error) {
	options := didsubject.DefaultCreationOptions()
	if request.Body.Subject != nil {
		options = options.With(didsubject.SubjectCreationOption{Subject: *request.Body.Subject})
	}
	if request.Body.Keys != nil {
		if request.Body.Keys.EncryptionKey {
			options = options.With(didsubject.EncryptionKeyCreationOption{})
		}
	}

	docs, subject, err := w.SubjectManager.Create(ctx, options)
	if err != nil {
		return nil, err
	}

	return CreateSubject200JSONResponse(SubjectCreationResult{
		Documents: docs,
		Subject:   subject,
	}), nil
}
func (w *Wrapper) ListSubjects(ctx context.Context, _ ListSubjectsRequestObject) (ListSubjectsResponseObject, error) {
	subjects, err := w.SubjectManager.List(ctx)
	if err != nil {
		return nil, err
	}
	response := make(map[string][]string)
	for subject, dids := range subjects {
		didStrings := make([]string, len(dids))
		for i, curr := range dids {
			didStrings[i] = curr.String()
		}
		response[subject] = didStrings
	}
	return ListSubjects200JSONResponse(response), nil
}

func (w *Wrapper) Deactivate(ctx context.Context, request DeactivateRequestObject) (DeactivateResponseObject, error) {
	err := w.SubjectManager.Deactivate(ctx, request.Id)
	if err != nil {
		return nil, err
	}
	return Deactivate204Response{}, nil
}

func (w *Wrapper) ResolveDID(_ context.Context, request ResolveDIDRequestObject) (ResolveDIDResponseObject, error) {
	targetDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	didDocument, metadata, err := w.VDR.Resolver().Resolve(*targetDID, nil)
	if err != nil {
		return nil, err
	}
	return ResolveDID200JSONResponse{
		Document:         *didDocument,
		DocumentMetadata: *metadata,
	}, nil
}

func (w *Wrapper) SubjectDIDs(ctx context.Context, request SubjectDIDsRequestObject) (SubjectDIDsResponseObject, error) {
	list, err := w.SubjectManager.ListDIDs(ctx, request.Id)

	if err != nil {
		return nil, err
	}
	result := make([]string, len(list))
	for i, curr := range list {
		result[i] = curr.String()
	}
	return SubjectDIDs200JSONResponse(result), nil
}

func (w *Wrapper) FindServices(ctx context.Context, request FindServicesRequestObject) (FindServicesResponseObject, error) {
	services, err := w.SubjectManager.FindServices(ctx, request.Id, request.Params.Type)
	if err != nil {
		return nil, err
	}

	var results []did.Service
	for _, service := range services {
		if request.Params.EndpointType != nil {
			// The value of the serviceEndpoint property MUST be a string, a map, or a set composed of one or more strings and/or maps.
			// All string values MUST be valid URIs conforming to [RFC3986] and normalized according to the Normalization and Comparison rules in RFC3986
			// and to any normalization rules in its applicable URI scheme specification.
			// (taken from https://www.w3.org/TR/did-core/#services)
			var endpointType string
			switch service.ServiceEndpoint.(type) {
			case string:
				endpointType = "string"
			case map[string]interface{}:
				endpointType = "object"
			case []map[string]interface{}:
				endpointType = "array"
			case []interface{}:
				endpointType = "array"
			}
			if string(*request.Params.EndpointType) != endpointType {
				continue
			}
		}
		results = append(results, service)
	}

	return FindServices200JSONResponse(results), nil
}

func (w *Wrapper) CreateService(ctx context.Context, request CreateServiceRequestObject) (CreateServiceResponseObject, error) {
	newServices, err := w.SubjectManager.CreateService(ctx, request.Id, *request.Body)
	if err != nil {
		return nil, err
	}
	return CreateService200JSONResponse(newServices), nil
}

func (w *Wrapper) DeleteService(ctx context.Context, request DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
	serviceID, err := ssi.ParseURI(request.ServiceId)
	if err != nil {
		return nil, err
	}
	err = w.SubjectManager.DeleteService(ctx, request.Id, *serviceID)
	if err != nil {
		return nil, err
	}
	return DeleteService204Response{}, nil
}

func (w *Wrapper) UpdateService(ctx context.Context, request UpdateServiceRequestObject) (UpdateServiceResponseObject, error) {
	serviceID, err := ssi.ParseURI(request.ServiceId)
	if err != nil {
		return nil, err
	}
	newServices, err := w.SubjectManager.UpdateService(ctx, request.Id, *serviceID, *request.Body)
	if err != nil {
		return nil, err
	}
	return UpdateService200JSONResponse(newServices), nil
}

func (w *Wrapper) AddVerificationMethod(ctx context.Context, request AddVerificationMethodRequestObject) (AddVerificationMethodResponseObject, error) {
	subject := request.Id
	keyUsage := orm.AssertionKeyUsage()
	if request.Body != nil {
		if request.Body.EncryptionKey {
			keyUsage ^= orm.EncryptionKeyUsage()
		}
		if !request.Body.AssertionKey {
			keyUsage ^= orm.AssertionKeyUsage()
		}
		if keyUsage == 0 {
			return nil, core.InvalidInputError("at least one key must be created")
		}
	}

	vms, err := w.SubjectManager.AddVerificationMethod(ctx, subject, keyUsage)
	if err != nil {
		return nil, err
	}
	return AddVerificationMethod200JSONResponse(vms), nil
}

// requestedWebDID constructs a did:web DID as it was requested by the API caller. It can be a DID with or without user path, e.g.:
// - did:web:example.com
// - did:web:example:iam:1234
// When userID is given, it's appended to the DID as `:iam:<userID>`. If it's absent, the DID is returned as is.
func (r Wrapper) requestedWebDID(userID string) did.DID {
	identityURL := r.VDR.PublicURL()
	if userID != "" {
		identityURL = identityURL.JoinPath("iam", userID)
	}
	result, _ := didweb.URLToDID(*identityURL)
	return *result
}
