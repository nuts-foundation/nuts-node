/*
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

package v0

import (
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
)

// ProviderMetadata is the metadata of the OpenID Connect provider
type ProviderMetadata = oidc4vci.ProviderMetadata

// CredentialIssuerMetadata is the metadata of the OIDC4VCI credential issuer
type CredentialIssuerMetadata = oidc4vci.CredentialIssuerMetadata

// TokenResponse is the response of the OpenID Connect token endpoint
type TokenResponse = oidc4vci.TokenResponse

// CredentialOfferResponse is the response to the OIDC4VCI credential offer
type CredentialOfferResponse = oidc4vci.CredentialOfferResponse

// CredentialRequest is the request to the OIDC4VCI credential request endpoint
type CredentialRequest = oidc4vci.CredentialRequest

// CredentialResponse is the response of the OIDC4VCI credential request endpoint
type CredentialResponse = oidc4vci.CredentialResponse

// OAuth2ClientMetadata is the metadata of the OAuth2 client
type OAuth2ClientMetadata = oidc4vci.OAuth2ClientMetadata

type ErrorResponse = oidc4vci.Error

var _ core.ErrorWriter = (*protocolErrorWriter)(nil)

type protocolErrorWriter struct {
}

func (p protocolErrorWriter) Write(echoContext echo.Context, _ int, _ string, err error) error {
	// If not already a protocol error, make it one (code=server_error).
	var protocolError oidc4vci.Error
	if !errors.As(err, &protocolError) {
		protocolError = oidc4vci.Error{
			Err:        err,
			Code:       oidc4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}
	// Make sure we don't accidentally return a 200 OK in case StatusCode is not set.
	if protocolError.StatusCode == 0 {
		protocolError.StatusCode = http.StatusInternalServerError
	}
	// OpenID4VCI errors contain an extra message which we don't want to return, so log it here.
	log.Logger().Warnf("OpenID4VCI error occurred (status %d): %s", protocolError.StatusCode, err)
	return echoContext.JSON(protocolError.StatusCode, protocolError)
}

var errHolderOrIssuerNotFound = oidc4vci.Error{
	Err:        errors.New("holder or issuer not found"),
	Code:       oidc4vci.InvalidRequest,
	StatusCode: http.StatusNotFound,
}

var _ StrictServerInterface = (*Wrapper)(nil)

// Wrapper wraps the OIDC4VCI API
type Wrapper struct {
	VCR           vcr.VCR
	DocumentOwner types.DocumentOwner
}

// Routes registers the API routes
func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vcr.ModuleName+"/OIDC4VCI")
				ctx.Set(core.ErrorWriterContextKey, &protocolErrorWriter{})
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, args interface{}) (interface{}, error) {
				if !w.VCR.OIDC4VCIEnabled() {
					log.Logger().Info("Someone tried to access disabled OIDC4VCI API endpoint.")
					return nil, core.NotFoundError("openid4vci is disabled")
				}
				return f(ctx, args)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vcr.ModuleName+"/OIDC4VCI", operationID)
		},
	}))
}

// validateDIDIsOwned parsed the given string as DID and checks whether it's owned by this node.
func (w Wrapper) validateDIDIsOwned(ctx context.Context, holderOrIssuerDID string) (did.DID, error) {
	parsedDID, err := did.ParseDID(holderOrIssuerDID)
	if err != nil {
		return did.DID{}, errHolderOrIssuerNotFound
	}
	isOwner, err := w.DocumentOwner.IsOwner(ctx, *parsedDID)
	if err != nil {
		return did.DID{}, err
	}
	if !isOwner {
		return did.DID{}, errHolderOrIssuerNotFound
	}
	return *parsedDID, nil
}
