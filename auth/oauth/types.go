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
}

const (
	// AuthzServerWellKnown is the well-known base path for the oauth authorization server metadata as defined in RFC8414
	AuthzServerWellKnown = "/.well-known/oauth-authorization-server"
	// openidCredIssuerWellKnown is the well-known base path for the openID credential issuer metadata as defined in OpenID4VCI specification
	openidCredIssuerWellKnown = "/.well-known/openid-credential-issuer"
	// openidCredWalletWellKnown is the well-known path element we created for openid4vci to retrieve the oauth client metadata
	openidCredWalletWellKnown = "/.well-known/openid-credential-wallet"
)

// IssuerIdToWellKnown converts the OAuth2 Issuer identity to the specified well-known endpoint by inserting the well-known at the root of the path.
// It returns no url and an error when issuer is not a valid URL.
func IssuerIdToWellKnown(issuer string, wellKnown string, strictmode bool) (*url.URL, error) {
	var issuerURL *url.URL
	var err error
	if strictmode {
		issuerURL, err = core.ParsePublicURL(issuer, false, "https")
	} else {
		issuerURL, err = core.ParsePublicURL(issuer, true, "https", "http")
	}
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
	PresentationDefinitionEndpoint string `json:"presentation_definition_endpoint,omitempty"`

	// PresentationDefinitionUriSupported specifies whether the Wallet supports the transfer of presentation_definition by reference, with true indicating support.
	// If omitted, the default value is true. (hence pointer, or add custom unmarshalling)
	PresentationDefinitionUriSupported *bool `json:"presentation_definition_uri_supported,omitempty"`

	// VPFormatsSupported is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Wallet.
	VPFormatsSupported map[string]map[string][]string `json:"vp_formats_supported,omitempty"`

	// VPFormats is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Verifier.
	VPFormats map[string]map[string][]string `json:"vp_formats,omitempty"`

	// ClientIdSchemesSupported defines the `client_id_schemes` currently supported.
	// If omitted, the default value is `pre-registered` (referring to the client), which is currently not supported.
	ClientIdSchemesSupported []string `json:"client_id_schemes_supported,omitempty"`
}

// ErrorResponse models an error returned from an OAuth flow according to RFC6749 (https://tools.ietf.org/html/rfc6749#page-45)
type ErrorResponse struct {
	Description *string `json:"error_description,omitempty"`
	Error       string  `json:"error"`
}
