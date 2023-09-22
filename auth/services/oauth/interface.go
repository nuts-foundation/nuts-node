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

package oauth

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"net/url"
)

// RelyingParty implements the OAuth2 relying party role.
type RelyingParty interface {
	CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error)

	// RequestRFC003AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC003.
	RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authServerEndpoint url.URL) (*oauth.TokenResponse, error)

	// RequestRFC021AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC021.
	RequestRFC021AccessToken(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes []string) (*oauth.TokenResponse, error)
}

// AuthorizationServer implements the OAuth2 authorization server role.
type AuthorizationServer interface {
	// Configure sets up the client. Enable secureMode to have it behave more safe (e.g., sanitize internal errors).
	Configure(clockSkewInMilliseconds int, secureMode bool) error
	// CreateAccessToken is called by remote Nuts nodes to create an access token,
	// which can be used to access the local organization's XIS resources.
	// It returns an oauth.ErrorResponse rather than a regular Go error, because the errors that may be returned are tightly specified.
	CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*oauth.TokenResponse, *oauth.ErrorResponse)
	IntrospectAccessToken(ctx context.Context, token string) (*services.NutsAccessToken, error)
}
