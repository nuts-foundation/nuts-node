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

package oidc4vci_v0

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
)

// ProviderMetadata is the metadata of the OpenID Connect provider
type ProviderMetadata = oidc4vci.ProviderMetadata

// CredentialIssuerMetadata is the metadata of the OIDC4VCI credential issuer
type CredentialIssuerMetadata = oidc4vci.CredentialIssuerMetadata

// TokenResponse is the response of the OpenID Connect token endpoint
type TokenResponse = oidc4vci.TokenResponse

// CredentialRequest is the request to the OIDC4VCI credential request endpoint
type CredentialRequest = oidc4vci.CredentialRequest

// CredentialResponse is the response of the OIDC4VCI credential request endpoint
type CredentialResponse = oidc4vci.CredentialResponse

// OAuth2ClientMetadata is the metadata of the OAuth2 client
type OAuth2ClientMetadata = oidc4vci.OAuth2ClientMetadata

// CredentialOffer is the credential offer sent to the OIDC4VCI wallet
type CredentialOffer = oidc4vci.CredentialOffer

var _ StrictServerInterface = (*Wrapper)(nil)

// Wrapper wraps the OIDC4VCI API
type Wrapper struct {
	VCR vcr.VCR
}

// Routes registers the API routes
func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vcr.ModuleName)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, args interface{}) (interface{}, error) {
				if !w.VCR.OIDC4VCIEnabled() {
					return nil, core.NotFoundError("") // check response
				}
				return f(ctx, args)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vcr.ModuleName, operationID)
		},
	}))
}
