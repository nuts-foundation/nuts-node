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

package implementation_documentation

import "net/url"

// Form OAuth 2.0 Authorization Server Metadata https://www.rfc-editor.org/rfc/rfc8414.html
type RFC8414Fields struct {
	Issuer string `json:"issuer"`
	//	REQUIRED.  The authorization server's issuer identifier, which is
	//	a URL that uses the "https" scheme and has no query or fragment
	//	components.  Authorization server metadata is published at a
	//	location that is ".well-known" according to RFC 5785 [RFC5785]
	//	derived from this issuer identifier, as described in Section 3.
	//	The issuer identifier is used to prevent authorization server mix-
	//	up attacks, as described in "OAuth 2.0 Mix-Up Mitigation"
	//[MIX-UP].

	AuthorizationEndpoint url.URL `json:"authorization_endpoint"`
	//	URL of the authorization server's authorization endpoint
	//[RFC6749].  This is REQUIRED unless no grant types are supported
	//	that use the authorization endpoint.

	TokenEndpoint url.URL `json:"token_endpoint"`
	//URL of the authorization server's token endpoint [RFC6749].  This
	//is REQUIRED unless only the implicit grant type is supported.

	// TODO: Can we use this for none-did:nuts wallets to get the public key?
	JwksURI url.URL `json:"jwks_uri"`
	//OPTIONAL.  URL of the authorization server's JWK Set [JWK]
	//document.  The referenced document contains the signing key(s) the
	//client uses to validate signatures from the authorization server.
	//This URL MUST use the "https" scheme.  The JWK Set MAY also
	//contain the server's encryption key or keys, which are used by
	//clients to encrypt requests to the server.  When both signing and
	//encryption keys are made available, a "use" (public key use)
	//parameter value is REQUIRED for all keys in the referenced JWK Set
	//to indicate each key's intended usage.

	// TODO: drop?
	RegistrationEndpoint url.URL `json:"registration_endpoint"`
	//OPTIONAL.  URL of the authorization server's OAuth 2.0 Dynamic
	//Client Registration endpoint [RFC7591].

	// NOTE: If added, should this be configurable or hardcoded?
	// Configurable allows specifying per care organization what use-cases are supported,
	// but that also requires configuration per care organization. Sounds like too much complexity for now.
	ScopesSupported []string `json:"scopes_supported"`
	//	RECOMMENDED.  JSON array containing a list of the OAuth 2.0
	//[RFC6749] "scope" values that this authorization server supports.
	//	Servers MAY choose not to advertise some supported scope values
	//	even when this parameter is used.

	// NOTE: currently ["code", "vp_token", "vp_token id_token"] vp_token standalone is used in eOverdracht notification?
	// RFC6749? specifies this `response_type` as an unordered list, so that applies here too?
	ResponseTypesSupported []string `json:"response_types_supported"`
	//REQUIRED.  JSON array containing a list of the OAuth 2.0
	//"response_type" values that this authorization server supports.
	//The array values used are the same as those used with the
	//"response_types" parameter defined by "OAuth 2.0 Dynamic Client
	//Registration Protocol" [RFC7591].

	// TODO: extend list ["query", "direct_post"]
	// From https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
	//		query
	//			In this mode, Authorization Response parameters are encoded in the query string added to the redirect_uri when redirecting back to the Client.
	//			For purposes of this specification, the default Response Mode for the OAuth 2.0 `code` Response Type is the `query` encoding.
	//		fragment (NOTE: should be removed since this is part of the deprecated implicit flow (response_type=token)?)
	//			In this mode, Authorization Response parameters are encoded in the fragment added to the redirect_uri when redirecting back to the Client.
	//			For purposes of this specification, the default Response Mode for the OAuth 2.0 `token` Response Type is the `fragment` encoding.
	// From https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
	//		form_post (TODO: do we want this?)
	//			In this mode, Authorization Response parameters are encoded as HTML form values that are auto-submitted in the User Agent,
	//			and thus are transmitted via the HTTP POST method to the Client, with the result parameters being encoded in the body using the application/x-www-form-urlencoded format.
	//			The action attribute of the form MUST be the Client's Redirection URI. The method of the form attribute MUST be POST.
	//			Because the Authorization Response is intended to be used only once,
	//			the Authorization Server MUST instruct the User Agent (and any intermediaries) not to store or reuse the content of the response.
	// From https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post
	//		direct_post
	//			In this mode, the Authorization Response is sent to the Verifier using an HTTPS POST request to an endpoint controlled by the Verifier.
	//			The Authorization Response parameters are encoded in the body using the application/x-www-form-urlencoded content type.
	//			The flow can end with an HTTPS POST request from the Wallet to the Verifier, or it can end with a redirect that follows the HTTPS POST request,
	//			if the Verifier responds with a redirect URI to the Wallet.
	//		direct_post.jwt
	//			same as direct post but data wrapped in a jwt
	//		TODO: direct_post.jwt allows putting a signature on the entire response (vp_token + id_token) if we ever need that
	ResponseModesSupported []string `json:"response_modes_supported"`
	//	OPTIONAL.  JSON array containing a list of the OAuth 2.0
	//	"response_mode" values that this authorization server supports, as
	//	specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
	//[OAuth.Responses].  If omitted, the default is "["query",
	//	"fragment"]".  The response mode value "form_post" is also defined
	//	in "OAuth 2.0 Form Post Response Mode" [OAuth.Post].

	// TODO: extend ["authorization_code", "vp_token" (s2s flow), "pre-authorized_code"]
	GrantTypesSupported []string `json:"grant_types_supported"`
	//OPTIONAL.  JSON array containing a list of the OAuth 2.0 grant
	//type values that this authorization server supports.  The array
	//values used are the same as those used with the "grant_types"
	//parameter defined by "OAuth 2.0 Dynamic Client Registration
	//Protocol" [RFC7591].  If omitted, the default value is
	//"["authorization_code", "implicit"]".

	// TODO: what do we support?
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	//	OPTIONAL.  JSON array containing a list of client authentication
	//	methods supported by this token endpoint.  Client authentication
	//	method values are used in the "token_endpoint_auth_method"
	//	parameter defined in Section 2 of [RFC7591].  If omitted, the
	//default is "client_secret_basic" -- the HTTP Basic Authentication
	//	Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].

	// TODO: what do we support?
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	//OPTIONAL.  JSON array containing a list of the JWS signing
	//algorithms ("alg" values) supported by the token endpoint for the
	//signature on the JWT [JWT] used to authenticate the client at the
	//token endpoint for the "private_key_jwt" and "client_secret_jwt"
	//authentication methods.  This metadata entry MUST be present if
	//either of these authentication methods are specified in the
	//"token_endpoint_auth_methods_supported" entry.  No default
	//algorithms are implied if this entry is omitted.  Servers SHOULD
	//support "RS256".  The value "none" MUST NOT be used.

	//TODO: drop or point to nuts rtd?
	ServiceDocumentation url.URL `json:"service_documentation"`
	//OPTIONAL.  URL of a page containing human-readable information
	//that developers might want or need to know when using the
	//authorization server.  In particular, if the authorization server
	//does not support Dynamic Client Registration, then information on
	//how to register clients needs to be provided in this
	//documentation.

	// TODO: drop
	UILocalesSupported []string `json:"ui_locales_supported"`
	//	OPTIONAL.  Languages and scripts supported for the user interface,
	//	represented as a JSON array of language tag values from BCP 47
	//[RFC5646].  If omitted, the set of supported languages and scripts
	//	is unspecified.

	// NOTE: `op` refers to openid provider
	// TODO: drop
	OPPolicyURI url.URL `json:"op_policy_uri"`
	//OPTIONAL.  URL that the authorization server provides to the
	//person registering the client to read about the authorization
	//server's requirements on how the client can use the data provided
	//by the authorization server.  The registration process SHOULD
	//display this URL to the person registering the client if it is
	//given.  As described in Section 5, despite the identifier
	//"op_policy_uri" appearing to be OpenID-specific, its usage in this
	//specification is actually referring to a general OAuth 2.0 feature
	//that is not specific to OpenID Connect.

	// TODO: drop
	OPTOSURI url.URL `json:"op_tos_uri"`
	//OPTIONAL.  URL that the authorization server provides to the
	//person registering the client to read about the authorization
	//server's terms of service.  The registration process SHOULD
	//display this URL to the person registering the client if it is
	//given.  As described in Section 5, despite the identifier
	//"op_tos_uri", appearing to be OpenID-specific, its usage in this
	//specification is actually referring to a general OAuth 2.0 feature
	//that is not specific to OpenID Connect.

	// TODO: do we want this?
	RevocationEndpoint url.URL `json:"revocation_endpoint"`
	//OPTIONAL.  URL of the authorization server's OAuth 2.0 revocation
	//endpoint [RFC7009].

	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	//	OPTIONAL.  JSON array containing a list of client authentication
	//	methods supported by this revocation endpoint.  The valid client
	//	authentication method values are those registered in the IANA
	//	"OAuth Token Endpoint Authentication Methods" registry
	//[IANA.OAuth.Parameters].  If omitted, the default is
	//	"client_secret_basic" -- the HTTP Basic Authentication Scheme
	//	specified in Section 2.3.1 of OAuth 2.0 [RFC6749].

	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	//OPTIONAL.  JSON array containing a list of the JWS signing
	//algorithms ("alg" values) supported by the revocation endpoint for
	//the signature on the JWT [JWT] used to authenticate the client at
	//the revocation endpoint for the "private_key_jwt" and
	//"client_secret_jwt" authentication methods.  This metadata entry
	//MUST be present if either of these authentication methods are
	//specified in the "revocation_endpoint_auth_methods_supported"
	//entry.  No default algorithms are implied if this entry is
	//omitted.  The value "none" MUST NOT be used.

	// TODO: we will have an introspection endpoint, but will it be public?
	IntrospectionEndpoint url.URL `json:"introspection_endpoint"`
	//OPTIONAL.  URL of the authorization server's OAuth 2.0
	//introspection endpoint [RFC7662].

	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	//	OPTIONAL.  JSON array containing a list of client authentication
	//	methods supported by this introspection endpoint.  The valid
	//	client authentication method values are those registered in the
	//	IANA "OAuth Token Endpoint Authentication Methods" registry
	//[IANA.OAuth.Parameters] or those registered in the IANA "OAuth
	//	Access Token Types" registry [IANA.OAuth.Parameters].  (These
	//	values are and will remain distinct, due to Section 7.2.)  If
	//	omitted, the set of supported authentication methods MUST be
	//	determined by other means.

	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	//OPTIONAL.  JSON array containing a list of the JWS signing
	//algorithms ("alg" values) supported by the introspection endpoint
	//for the signature on the JWT [JWT] used to authenticate the client
	//at the introspection endpoint for the "private_key_jwt" and
	//"client_secret_jwt" authentication methods.  This metadata entry
	//MUST be present if either of these authentication methods are
	//specified in the "introspection_endpoint_auth_methods_supported"
	//entry.  No default algorithms are implied if this entry is
	//omitted.  The value "none" MUST NOT be used.

	// TODO: Probably good to add?
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	//	OPTIONAL.  JSON array containing a list of Proof Key for Code
	//	Exchange (PKCE) [RFC7636] code challenge methods supported by this
	//	authorization server.  Code challenge method values are used in
	//	the "code_challenge_method" parameter defined in Section 4.3 of
	//[RFC7636].  The valid code challenge method values are those
	//	registered in the IANA "PKCE Code Challenge Methods" registry
	//[IANA.OAuth.Parameters].  If omitted, the authorization server
	//	does not support PKCE.
}

// OpenID4VPFields contains all fields defined in the OpenID4VP specification https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-wallet-metadata-authorizati
type OpenID4VPFields struct {
	// NOTE: default is true
	PresentationDefinitionUriSupported *bool `json:"presentation_definition_uri_supported,omitempty"`
	//OPTIONAL. Boolean value specifying whether the Wallet supports the transfer of presentation_definition by reference, with true indicating support. If omitted, the default value is true.

	// following NCSC guidelines
	VPFormatsSupported map[string]any `json:"vp_formats_supported,omitempty"`
	//REQUIRED. An object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Wallet.
	//Valid Credential format identifier values are defined in Annex E of [OpenID.VCI]. Other values may be used when defined in the profiles of this specification.
	//The value is an object containing a parameter defined below:
	//	alg_values_supported:
	//	An object where the value is an array of case sensitive strings that identify the cryptographic suites that are supported.
	//	Parties will need to agree upon the meanings of the values used, which may be context-specific.
	//	For specific values that can be used depending on the Credential format, see Appendix A.
	//
	//The following is a non-normative example of a vp_formats_supported parameter:
	//	"vp_formats_supported": {
	//		 "jwt_vc_json": {
	//			 "alg_values_supported": ["ES256K", "ES384"]
	//		 },
	//		 "jwt_vp_json": {
	//			"alg_values_supported": ["ES256K", "EdDSA"]
	//		 }
	//	}

	// We are using ["did"]
	ClientIdSchemesSupported []string `json:"client_id_schemes_supported,omitempty"`
	//OPTIONAL. Array of JSON Strings containing the values of the Client Identifier schemes that the Wallet supports.
	//The values defined by this specification are pre-registered, redirect_uri, entity_id, did. If omitted, the default value is pre-registered.
	//Other values may be used when defined in the profiles of this specification.
}

// OpenID4VCIFields contains all fields defined in the OpenID4VCI specification https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv
type OpenID4VCIFields struct {
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported"`
	//OPTIONAL. A JSON Boolean indicating whether the issuer accepts a Token Request with a Pre-Authorized Code but without a client id. The default is false.
}
