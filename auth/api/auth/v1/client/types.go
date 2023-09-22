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

package client

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
)

// JwtBearerGrantType defines the grant-type to use in the access token request
const JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// VerifiableCredential is an alias to use from within the API
type VerifiableCredential = vc.VerifiableCredential

// VerifiablePresentation is an alias to use from within the API
type VerifiablePresentation = vc.VerifiablePresentation

// AccessTokenResponse is an alias to use from within the API
type AccessTokenResponse = oauth.TokenResponse
