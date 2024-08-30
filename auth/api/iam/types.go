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

package iam

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// DIDDocument is an alias
type DIDDocument = did.Document

// DIDDocumentMetadata is an alias
type DIDDocumentMetadata = resolver.DocumentMetadata

// VerifiablePresentation is an alias
type VerifiablePresentation = vc.VerifiablePresentation

// VerifiableCredential is an alias
type VerifiableCredential = vc.VerifiableCredential

// ErrorResponse is an alias
type ErrorResponse = oauth.OAuth2Error

// PresentationDefinition is an alias
type PresentationDefinition = pe.PresentationDefinition

// PresentationSubmission is an alias
type PresentationSubmission = pe.PresentationSubmission

type RedirectResponse = oauth.Redirect

// TokenResponse is an alias
type TokenResponse = oauth.TokenResponse

// OAuthAuthorizationServerMetadata is an alias
type OAuthAuthorizationServerMetadata = oauth.AuthorizationServerMetadata

// OAuthClientMetadata is an alias
type OAuthClientMetadata = oauth.OAuthClientMetadata

// WalletOwnerType is an alias
type WalletOwnerType = pe.WalletOwnerType

// RequiredPresentationDefinitions is an alias
type RequiredPresentationDefinitions = pe.WalletOwnerMapping

const (
	// responseModeQuery returns the answer to the authorization request append as query parameters to the provided redirect_uri
	responseModeQuery = "query" // default if no response_mode is specified
	// responseModeDirectPost signals the Authorization Server to POST the requested presentation definition to the provided response_uri
	responseModeDirectPost = "direct_post"
)

var responseModesSupported = []string{responseModeQuery, responseModeDirectPost}

var responseTypesSupported = []string{oauth.CodeResponseType, oauth.VPTokenResponseType}

var grantTypesSupported = []string{oauth.AuthorizationCodeGrantType, oauth.VpTokenGrantType}

var clientIdSchemesSupported = []string{entityClientIDScheme}

// didClientIDScheme is the client_id_scheme value for DIDs
const didClientIDScheme = "did"

const entityClientIDScheme = "entity_id"

const (
	AccessTokenTypeBearer = "Bearer"
	AccessTokenTypeDPoP   = "DPoP"
)
