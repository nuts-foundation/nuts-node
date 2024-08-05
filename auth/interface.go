/*
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

package auth

import (
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"net/url"
)

// ModuleName contains the name of this module
const ModuleName = "Auth"

// AuthenticationServices is the interface which should be implemented for clients or mocks
type AuthenticationServices interface {
	// AuthzServer returns the oauth.AuthorizationServer
	AuthzServer() oauth.AuthorizationServer
	// IAMClient returns the IAM Client API
	IAMClient() iam.Client
	// RelyingParty returns the oauth.RelyingParty
	RelyingParty() oauth.RelyingParty
	// ContractNotary returns an instance of ContractNotary
	ContractNotary() services.ContractNotary
	// PublicURL returns the public URL of the node.
	PublicURL() *url.URL
	// AuthorizationEndpointEnabled returns whether the v2 API's OAuth2 Authorization Endpoint is enabled.
	AuthorizationEndpointEnabled() bool
}
