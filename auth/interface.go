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
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
)

// AuthenticationServices is the interface which should be implemented for clients or mocks
type AuthenticationServices interface {
	// AuthzServer returns the oauth.AuthorizationServer
	AuthzServer() oauth.AuthorizationServer
	// RelyingParty returns the oauth.RelyingParty
	RelyingParty() oauth.RelyingParty
	// ContractNotary returns an instance of ContractNotary
	ContractNotary() services.ContractNotary
	// NextGenOAuth2Enabled returns true if the Next-Gen OAuth2 API is enabled
	NextGenOAuth2Enabled() bool
}
