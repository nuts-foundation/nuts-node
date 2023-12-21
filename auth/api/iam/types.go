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
	"time"
)

// DIDDocument is an alias
type DIDDocument = did.Document

// DIDDocumentMetadata is an alias
type DIDDocumentMetadata = resolver.DocumentMetadata

// VerifiablePresentation is an alias
type VerifiablePresentation = vc.VerifiablePresentation

// ErrorResponse is an alias
type ErrorResponse = oauth.OAuth2Error

// PresentationDefinition is an alias
type PresentationDefinition = pe.PresentationDefinition

// TokenResponse is an alias
type TokenResponse = oauth.TokenResponse

// OAuthAuthorizationServerMetadata is an alias
type OAuthAuthorizationServerMetadata = oauth.AuthorizationServerMetadata

// OAuthClientMetadata is an alias
type OAuthClientMetadata = oauth.OAuthClientMetadata

const (
	sessionExpiry = 5 * time.Minute
)

const (
	// responseTypeParam is the name of the response_type parameter.
	// Specified by https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
	//
	// TODO: reconsider the following
	//	Extension response types MAY contain a space-delimited (%x20) list of
	//	values, where the order of values does not matter (e.g., response
	//	type "a b" is the same as "b a").  The meaning of such composite
	//	response types is defined by their respective specifications.
	//
	//	If an authorization request is missing the "response_type" parameter,
	//	or if the response type is not understood, the authorization server
	//	MUST return an error response as described in Section 4.1.2.1.
	responseTypeParam = "response_type"
	// responseTypeCode is the default response_type in the OAuth2 authorized code flow
	responseTypeCode = "code"
	// responseTypeVPToken is defined in the OpenID4VP vp_token flow
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#appendix-B
	responseTypeVPToken = "vp_token"
	// responseTypeVPIDToken is defined in the OpenID4VP flow that combines its vp_token with SIOPv2's id_token
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#appendix-B
	responseTypeVPIDToken = "vp_token id_token"
	nonceParam            = "nonce"
)

var responseTypesSupported = []string{responseTypeCode, responseTypeVPToken, responseTypeVPIDToken}

const (
	// didScheme is the client_id_scheme value for DIDs
	didScheme = "did"
	// responseModeParam is the name of the OAuth2 response_mode parameter.
	// Specified by https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
	responseModeParam = "response_mode"
	// responseModeQuery returns the answer to the authorization request append as query parameters to the provided redirect_uri
	responseModeQuery = "query" // default if no response_mode is specified
	// responseModeDirectPost signals the Authorization Server to POST the requested presentation definition to the provided response_uri
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post
	responseModeDirectPost = "direct_post"
)

var responseModesSupported = []string{responseModeQuery, responseModeDirectPost}

const (
	// grantTypeAuthorizationCode is the default OAuth2 grant type
	grantTypeAuthorizationCode = "authorization_code"
	// grantTypeVPToken is used to present a vp_token in exchange for an access_token in service-to-service flows
	// TODO: EBSI inspired flow that is not standardized
	// 		 https://api-conformance.ebsi.eu/docs/ct/verifiable-presentation-exchange-guidelines-v3#service-to-service-token-flow
	grantTypeVPToken = "vp_token"
	// grantTypePreAuthorizedCode is defined in the pre-authorized_code flow of OpenID4VCI
	// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sub-namespace-registration
	grantTypePreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

var grantTypesSupported = []string{grantTypeAuthorizationCode, grantTypeVPToken, grantTypePreAuthorizedCode}

// clientIdSchemesSupported lists the supported client_id_scheme
// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-managemen
var clientIdSchemesSupported = []string{"did"}

// clientIDParam is the name of the client_id parameter.
// Specified by https://datatracker.ietf.org/doc/html/rfc6749#section-2.2
const clientIDParam = "client_id"

// clientMetadataParam is the name of the OpenID4VP client_metadata parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-authorization-request
const clientMetadataParam = "client_metadata"

// clientMetadataParam is the name of the OpenID4VP client_metadata_uri parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-authorization-request
const clientMetadataURIParam = "client_metadata_uri"

// clientIDSchemeParam is the name of the OpenID4VP client_id_scheme parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-authorization-request
const clientIDSchemeParam = "client_id_scheme"

// scopeParam is the name of the scope parameter.
// Specified by https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
const scopeParam = "scope"

// stateParam is the name of the state parameter.
// Specified by https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
const stateParam = "state"

// redirectURIParam is the name of the redirect_uri parameter.
// Specified by https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
const redirectURIParam = "redirect_uri"

// responseURIParam is the name of the OpenID4VP response_uri parameter.
const responseURIParam = "response_uri"

// presentationDefParam is the name of the OpenID4VP presentation_definition parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-presentation_definition-par
const presentationDefParam = "presentation_definition"

// presentationDefUriParam is the name of the OpenID4VP presentation_definition_uri parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-presentation_definition_uri
const presentationDefUriParam = "presentation_definition_uri"

// presentationSubmissionParam is the name of the OpenID4VP presentation_submission parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-response-parameters
const presentationSubmissionParam = "presentation_submission"

// vpTokenParam is the name of the OpenID4VP vp_token parameter.
// Specified by https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-response-type-vp_token
const vpTokenParam = "vp_token"
