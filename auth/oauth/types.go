/*
 * Nuts node
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
 */

// Package oauth contains generic OAuth related functionality, variables and constants
package oauth

import (
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
)

// this file contains constants, variables and helper functions for OAuth related code

// TokenResponse is the OAuth access token response
type TokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   *int    `json:"expires_in,omitempty"`
	TokenType   string  `json:"token_type"`
	CNonce      *string `json:"c_nonce,omitempty"`
	Scope       *string `json:"scope,omitempty"`
	Status      *string `json:"status,omitempty"`
}

const (
	// AccessTokenRequestStatusPending is the status for a pending access token
	AccessTokenRequestStatusPending = "pending"
	// AccessTokenRequestStatusActive is the status for an active access token
	AccessTokenRequestStatusActive = "active"
)

const (
	// AuthzServerWellKnown is the well-known base path for the oauth authorization server metadata as defined in RFC8414
	AuthzServerWellKnown = "/.well-known/oauth-authorization-server"
	// ClientMetadataPath is the path to the client metadata relative to the complete did:web URL
	ClientMetadataPath = "/oauth-client"
	// openidCredIssuerWellKnown is the well-known base path for the openID credential issuer metadata as defined in OpenID4VCI specification
	openidCredIssuerWellKnown = "/.well-known/openid-credential-issuer"
	// openidCredWalletWellKnown is the well-known path element we created for openid4vci to retrieve the oauth client metadata
	openidCredWalletWellKnown = "/.well-known/openid-credential-wallet"
	// AssertionParam is the parameter name for the assertion parameter
	AssertionParam = "assertion"
	// AuthorizationCodeGrantType is the grant_type for the authorization_code grant type
	AuthorizationCodeGrantType = "authorization_code"
	// ClientIDParam is the parameter name for the client_id parameter
	ClientIDParam = "client_id"
	// CodeParam is the parameter name for the code parameter
	CodeParam = "code"
	// GrantTypeParam is the parameter name for the grant_type parameter
	GrantTypeParam = "grant_type"
	// NonceParam is the parameter name for the nonce parameter
	NonceParam = "nonce"
	// MaxAgeParam is the parameter name for the max_age parameter
	MaxAgeParam = "max_age"
	// RedirectURIParam is the parameter name for the redirect_uri parameter
	RedirectURIParam = "redirect_uri"
	// RequestParam is the parameter name for the request parameter
	RequestParam = "request"
	// ResponseTypeParam is the parameter name for the response_type parameter
	ResponseTypeParam = "response_type"
	// ScopeParam is the parameter name for the scope parameter
	ScopeParam = "scope"
	// StateParam is the parameter name for the state parameter
	StateParam = "state"
	// PresentationSubmissionParam is the parameter name for the presentation_submission parameter
	PresentationSubmissionParam = "presentation_submission"
	// VpTokenParam is the parameter name for the vp_token parameter
	VpTokenParam = "vp_token"
	// VpTokenGrantType is the grant_type for the vp_token-bearer grant type
	VpTokenGrantType = "vp_token-bearer"
)

const (
	// ErrorParam is the parameter name for the error parameter
	ErrorParam = "error"
	// ErrorDescriptionParam is the parameter name for the error_description parameter
	ErrorDescriptionParam = "error_description"
)

// IssuerIdToWellKnown converts the OAuth2 Issuer identity to the specified well-known endpoint by inserting the well-known at the root of the path.
// It returns no url and an error when issuer is not a valid URL.
func IssuerIdToWellKnown(issuer string, wellKnown string, strictmode bool) (*url.URL, error) {
	issuerURL, err := core.ParsePublicURL(issuer, strictmode)
	if err != nil {
		return nil, err
	}
	return issuerURL.Parse(wellKnown + issuerURL.EscapedPath())
}

// AuthorizationServerMetadata defines the OAuth Authorization Server metadata.
// Specified by https://www.rfc-editor.org/rfc/rfc8414.txt
type AuthorizationServerMetadata struct {
	// Issuer defines the authorization server's identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	Issuer string `json:"issuer"`

	/* ******** /authorize ******** */

	// AuthorizationEndpoint defines the URL of the authorization server's authorization endpoint [RFC6749]
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// ResponseTypesSupported defines what response types a client can request
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// ResponseModesSupported defines what response modes a client can request
	// Currently supports
	// - query for response_type=code
	// - direct_post for response_type=["vp_token", "vp_token id_token"]
	// TODO: is `form_post` something we want in the future?
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	/* ******** /token ******** */

	// TokenEndpoint defines the URL of the authorization server's token endpoint [RFC6749].
	TokenEndpoint string `json:"token_endpoint"`

	// GrantTypesSupported is a list of the OAuth 2.0 grant type values that this authorization server supports.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	//// TODO: what do we support?
	//// TokenEndpointAuthMethodsSupported is a JSON array containing a list of client authentication methods supported by this token endpoint.
	//// Client authentication method values are used in the "token_endpoint_auth_method" parameter defined in Section 2 of [RFC7591].
	//// If omitted, the default is "client_secret_basic" -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	//TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	//
	//// TODO: May be needed depending on TokenEndpointAuthMethodsSupported
	//// TokenEndpointAuthSigningAlgValuesSupported is a JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the token endpoint
	//// for the signature on the JWT [JWT] used to authenticate the client at the token endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	//// This metadata entry MUST be present if either of these authentication methods are specified in the "token_endpoint_auth_methods_supported" entry.
	//// No default algorithms are implied if this entry is omitted. Servers SHOULD support "RS256". The value "none" MUST NOT be used.
	//TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	/* ******** openid4vc ******** */

	// PreAuthorizedGrantAnonymousAccessSupported indicates whether anonymous access (requests without client_id) for pre-authorized code grant flows.
	// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported,omitempty"`

	// PresentationDefinitionEndpoint defines the URL of the authorization server's presentation definition endpoint.
	// See https://nuts-foundation.gitbook.io/drafts/rfc/rfc021-vp_token-grant-type
	PresentationDefinitionEndpoint string `json:"presentation_definition_endpoint,omitempty"`

	// PresentationDefinitionUriSupported specifies whether the Wallet supports the transfer of presentation_definition by reference, with true indicating support.
	// If omitted, the default value is true. (hence pointer, or add custom unmarshalling)
	PresentationDefinitionUriSupported *bool `json:"presentation_definition_uri_supported,omitempty"`

	// RequireSignedRequestObject specifies if the authorization server requires the use of signed request objects.
	RequireSignedRequestObject bool `json:"require_signed_request_object,omitempty"`

	// VPFormatsSupported is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Wallet.
	VPFormatsSupported map[string]map[string][]string `json:"vp_formats_supported,omitempty"`

	// VPFormats is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Verifier.
	VPFormats map[string]map[string][]string `json:"vp_formats,omitempty"`

	// ClientIdSchemesSupported defines the `client_id_schemes` currently supported.
	// If omitted, the default value is `pre-registered` (referring to the client), which is currently not supported.
	ClientIdSchemesSupported []string `json:"client_id_schemes_supported,omitempty"`
}

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
	VPFormats map[string]map[string][]string `json:"vp_formats,omitempty"`

	// ClientIdScheme is a string identifying the Client Identifier scheme. The value range defined by this specification is
	// pre-registered, redirect_uri, entity_id, did. If omitted, the default value is pre-registered.
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-client-me
	ClientIdScheme string `json:"client_id_scheme,omitempty"`
}

// Redirect is the response from the verifier on the direct_post authorization response.
type Redirect struct {
	// RedirectURI is the URI to redirect the user-agent to.
	RedirectURI string `json:"redirect_uri"`
}
