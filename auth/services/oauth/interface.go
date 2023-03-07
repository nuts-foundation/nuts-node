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
	"github.com/nuts-foundation/nuts-node/auth/services"
	"net/url"
)

// Client is the client interface for the OAuth service
type Client interface {
	// Configure sets up the client. Enable secureMode to have it behave more safe (e.g., sanitize internal errors).
	Configure(clockSkewInMilliseconds int, secureMode bool) error
	// RequestAccessToken is called by the local EHR node to request an access token from a remote Nuts node.
	RequestAccessToken(ctx context.Context, jwtGrantToken string, authServerEndpoint string) (*services.AccessTokenResult, error)
	// CreateAccessToken is called by remote Nuts nodes to create an access token,
	// which can be used to access the local organization's XIS resources.
	// It returns an oauth.ErrorResponse rather than a regular Go error, because the errors that may be returned are tightly specified.
	CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*services.AccessTokenResult, *ErrorResponse)
	CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error)
	GetOAuthEndpointURL(service string, authorizer did.DID) (url.URL, error)
	IntrospectAccessToken(token string) (*services.NutsAccessToken, error)
}
