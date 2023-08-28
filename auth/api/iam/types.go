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

// responseType
// TODO: reconsider the following
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
//
//	Extension response types MAY contain a space-delimited (%x20) list of
//	values, where the order of values does not matter (e.g., response
//	type "a b" is the same as "b a").  The meaning of such composite
//	response types is defined by their respective specifications.
//
//	If an authorization request is missing the "response_type" parameter,
//	or if the response type is not understood, the authorization server
//	MUST return an error response as described in Section 4.1.2.1.
type responseType = string

const (
	// responseTypeCode is the default response_type in the OAuth2 authorized code flow
	responseTypeCode responseType = "code"
	// responseTypeVPToken is defined in the OpenID4VP vp_token flow
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#appendix-B
	responseTypeVPToken responseType = "vp_token"
	// responseTypeVPIDToken is defined in the OpenID4VP flow that combines its vp_token with SIOPv2's id_token
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#appendix-B
	responseTypeVPIDToken responseType = "vp_token id_token"
)

var responseTypesSupported = []responseType{responseTypeCode, responseTypeVPToken, responseTypeVPIDToken}

// responseMode
type responseMode = string

const (
	// responseModeQuery returns the answer to the authorization request append as query parameters to the provided redirect_uri
	responseModeQuery responseMode = "query" // default if no response_mode is specified
	// responseModeDirectPost signals the Authorization Server to POST the requested presentation definition to the provided response_uri
	// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post
	responseModeDirectPost responseMode = "direct_post"
)

var responseModesSupported = []responseMode{responseModeQuery, responseModeDirectPost}

// grantType
type grantType = string

const (
	// grantTypeAuthorizationCode is the default OAuth2 grant type
	grantTypeAuthorizationCode grantType = "authorization_code"
	// grantTypeVPToken is used to present a vp_token in exchange for an access_token in service-to-service flows
	// TODO: EBSI inspired flow that is not standardized
	// 		 https://api-conformance.ebsi.eu/docs/ct/verifiable-presentation-exchange-guidelines-v3#service-to-service-token-flow
	grantTypeVPToken grantType = "vp_token"
	// grantTypePreAuthorizedCode is defined in the pre-authorized_code flow of OpenID4VCI
	// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sub-namespace-registration
	grantTypePreAuthorizedCode grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

var grantTypesSupported = []grantType{grantTypeAuthorizationCode, grantTypeVPToken, grantTypePreAuthorizedCode}

// algValuesSupported contains a list of supported cipher suites for jwt_vc_json & jwt_vp_json presentation formats
// Recommended list of options https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// TODO: validate list, should reflect current recommendations from https://www.ncsc.nl
var algValuesSupported = []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// proofTypeValuesSupported contains a list of supported cipher suites for ldp_vc & ldp_vp presentation formats
// Recommended list of options https://w3c-ccg.github.io/ld-cryptosuite-registry/
var proofTypeValuesSupported = []string{"JsonWebSignature2020"}

// vpFormatsSupported defines the supported formats and is used in the
//   - Authorization Server's metadata field `vp_formats_supported`
//   - Client's metadata field `vp_formats`
//
// TODO: spec is very unclear about this part.
// See https://github.com/nuts-foundation/nuts-node/issues/2447
var vpFormatsSupported = map[string]map[string][]string{
	"jwt_vp": {"alg_values_supported": algValuesSupported},
	"ldp_vc": {"proof_type_values_supported": proofTypeValuesSupported},
}

// clientIdSchemesSupported lists the supported client_id_scheme
// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-managemen
var clientIdSchemesSupported = []string{"did"}

// OAuthAuthorizationServerMetadata defines the OAuth Authorization Server metadata.
// Specified by https://www.rfc-editor.org/rfc/rfc8414.txt
type OAuthAuthorizationServerMetadata struct {
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
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported"`

	// PresentationDefinitionUriSupported specifies whether the Wallet supports the transfer of presentation_definition by reference, with true indicating support.
	// If omitted, the default value is true. (hence pointer, or add custom unmarshalling)
	PresentationDefinitionUriSupported *bool `json:"presentation_definition_uri_supported,omitempty"`

	// VPFormatsSupported is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Wallet.
	VPFormatsSupported map[string]map[string][]string `json:"vp_formats_supported,omitempty"`

	// ClientIdSchemesSupported defines the `client_id_schemes` currently supported.
	// If omitted, the default value is `pre-registered` (referring to the client), which is currently not supported.
	ClientIdSchemesSupported []string `json:"client_id_schemes_supported,omitempty"`
}
