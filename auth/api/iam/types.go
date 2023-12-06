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

// ErrorResponse is an alias
type ErrorResponse = oauth.OAuth2Error

// PresentationDefinition is an alias
type PresentationDefinition = pe.PresentationDefinition

// TokenResponse is an alias
type TokenResponse = oauth.TokenResponse

// OAuthAuthorizationServerMetadata is an alias
type OAuthAuthorizationServerMetadata = oauth.AuthorizationServerMetadata

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
)

var responseTypesSupported = []string{responseTypeCode, responseTypeVPToken, responseTypeVPIDToken}

const (
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

// OAuthClientMetadata defines the OAuth Client metadata.
// Specified by https://www.rfc-editor.org/rfc/rfc7591.html and elsewhere.
type OAuthClientMetadata struct {
	// RedirectURIs lists all URIs that the client may use in any redirect-based flow.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// TODO: What do we use? Must provide a value if its not "client_secret_basic"
	// TokenEndpointAuthMethod indicator of the requested authentication method for the token endpoint.
	// If unspecified or omitted, the default is "client_secret_basic", denoting the HTTP Basic authentication scheme as specified in Section 2.3.1 of OAuth 2.0.
	// Examples are: none, client_secret_post, client_secret_basic, tls_client_auth.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	// TODO: Can "tls_client_auth" replace /n2n/ for pre-authorized_code flow? https://www.rfc-editor.org/rfc/rfc8705.html
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes lists all supported grant_types. Defaults to "authorization_code" if omitted.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes lists all supported response_types. Defaults to "code". Must contain the values corresponding to listed GrantTypes.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	ResponseTypes []string `json:"response_types,omitempty"`

	// Scope contains a space-separated list of scopes the client can request.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	// TODO: I don't see the use for this. The idea is that an AS does not assign scopes to a client that it does not support (or wants to request at any time), but seems like unnecessary complexity for minimal safety.
	Scope string `json:"scope,omitempty"`

	// Contacts contains an array of strings representing ways to contact people responsible for this client, typically email addresses.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	// TODO: remove? Can plug DID docs contact info.
	Contacts []string `json:"contacts,omitempty"`

	// JwksURI URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	// TODO: remove? Can list the DID's keys. Could be useful if authorization without DIDs/VCs is needed.
	// TODO: In EBSI it is a required field for the Service Wallet Metadata https://api-conformance.ebsi.eu/docs/ct/providers-and-wallets-metadata#service-wallet-metadata
	JwksURI string `json:"jwks_uri,omitempty"`
	// Jwks includes the JWK Set of a client. Mutually exclusive with JwksURI.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	Jwks any `json:"jwks,omitempty"`

	// SoftwareID is a unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer.
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	SoftwareID string `json:"software_id,omitempty"`
	// SoftwareVersion is a version identifier string for the client software identified by "software_id".
	// From https://www.rfc-editor.org/rfc/rfc7591.html
	// TODO: Including a software_id + software_version could provide us with some upgrade paths in the future.
	SoftwareVersion string `json:"software_version,omitempty"`

	// TODO: ignored values: client_name, client_uri, logo_uri, tos_uri, policy_uri.
	// TODO: Things like client_name and logo may enhance the user experience when asking to accept authorization requests, but this should probably be added on the server size for that?

	/*********** OpenID4VCI ***********/

	// CredentialOfferEndpoint contains a URL where the pre-authorized_code flow offers a credential.
	// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata
	// TODO: openid4vci duplicate. Also defined on /.well-known/openid-credential-wallet to be /n2n/identity/{did}/openid4vci/credential_offer
	CredentialOfferEndpoint string `json:"credential_offer_endpoint,omitempty"`

	/*********** OpenID4VP ***********/
	// VPFormats lists the vp_formats supported by the client. See additional comments on vpFormatsSupported.
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-client-me
	VPFormats any `json:"vp_formats,omitempty"`

	// ClientIdScheme is a string identifying the Client Identifier scheme. The value range defined by this specification is
	// pre-registered, redirect_uri, entity_id, did. If omitted, the default value is pre-registered.
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-client-me
	ClientIdScheme string `json:"client_id_scheme,omitempty"`
}
