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
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
)

// this file contains constants, variables and helper functions for OAuth related code

// TokenResponse is the OAuth access token response.
// Through With() and Get() additional parameters (for OpenID4VCI, for instance) can be set and retrieved.
type TokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   *int    `json:"expires_in,omitempty"`
	TokenType   string  `json:"token_type"`
	Scope       *string `json:"scope,omitempty"`

	additionalParams map[string]interface{}
}

var _ json.Unmarshaler = (*TokenResponse)(nil)
var _ json.Marshaler = (*TokenResponse)(nil)

func (t *TokenResponse) UnmarshalJSON(data []byte) error {
	type Alias TokenResponse
	var result Alias
	// base parameters
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	// extension parameters
	additionalParams := map[string]interface{}{}
	_ = json.Unmarshal(data, &additionalParams) // can't fail, already unmarshalled
	delete(additionalParams, "access_token")
	delete(additionalParams, "expires_in")
	delete(additionalParams, "token_type")
	delete(additionalParams, "scope")
	*t = TokenResponse(result)
	if len(additionalParams) > 0 {
		t.additionalParams = additionalParams
	}
	return nil
}

func (t TokenResponse) MarshalJSON() ([]byte, error) {
	result := make(map[string]interface{})
	for key, value := range t.additionalParams {
		result[key] = value
	}
	result["access_token"] = t.AccessToken
	result["expires_in"] = t.ExpiresIn
	result["token_type"] = t.TokenType
	result["scope"] = t.Scope

	return json.Marshal(result)
}

// With adds a parameter to the token response.
// It's a builder-style function.
// It should not be used to set any of the base parameters (access_token, expires_in, token_type, scope).
func (t *TokenResponse) With(key string, value interface{}) *TokenResponse {
	if t.additionalParams == nil {
		t.additionalParams = make(map[string]interface{})
	}
	t.additionalParams[key] = value
	return t
}

// Get returns the value of the additional parameter with the given key as a string.
// If the key does not exist or the value is not a string, it returns an empty string.
// It should not be used to get any of the base parameters (access_token, expires_in, token_type, scope).
func (t TokenResponse) Get(key string) string {
	if t.additionalParams == nil {
		return ""
	}
	if val, ok := t.additionalParams[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

const (
	// AccessTokenRequestStatusPending is the status for a pending access token
	AccessTokenRequestStatusPending = "pending"
	// AccessTokenRequestStatusActive is the status for an active access token
	AccessTokenRequestStatusActive = "active"
)

// metadata endpoints
const (
	// AuthzServerWellKnown is the well-known base path for the oauth authorization server metadata as defined in RFC8414
	AuthzServerWellKnown = "/.well-known/oauth-authorization-server"
	// ClientMetadataPath is the path to the client metadata relative to the complete did:web URL
	ClientMetadataPath = "/oauth-client"
	// OpenIdCredIssuerWellKnown is the well-known base path for the openID credential issuer metadata as defined in
	// OpenID4VCI specification
	OpenIdCredIssuerWellKnown = "/.well-known/openid-credential-issuer"
	// OpenIdConfigurationWellKnown is the well-known base path for the openID configuration metadata as defined in
	// OpenID4 federation specification
	OpenIdConfigurationWellKnown = "/.well-known/openid-configuration"
)

// oauth parameter keys
const (
	// AssertionParam is the parameter name for the assertion parameter. (RFC021)
	AssertionParam = "assertion"
	// AuthorizationDetailsParam is the parameter name for the authorization_details parameter. (RFC9396)
	AuthorizationDetailsParam = "authorization_details"
	// ClientIDParam is the parameter name for the client_id parameter. (RFC6749)
	ClientIDParam = "client_id"
	// ClientIDSchemeParam is the parameter name for the client_id_scheme parameter. (OpenID4VP)
	ClientIDSchemeParam = "client_id_scheme"
	// ClientMetadataParam is the parameter name for the client_metadata parameter. (OpenID4VP)
	ClientMetadataParam = "client_metadata"
	// ClientMetadataURIParam is the parameter name for the client_metadata_uri parameter. (OpenID4VP)
	ClientMetadataURIParam = "client_metadata_uri"
	// CNonceParam is the parameter name for the c_nonce parameter. (OpenID4VCI)
	CNonceParam = "c_nonce"
	// CodeParam is the parameter name for the code parameter. (RFC6749)
	CodeParam = CodeResponseType
	// CodeChallengeParam is the parameter name for the code_challenge parameter. (RFC7636)
	CodeChallengeParam = "code_challenge"
	// CodeChallengeMethodParam is the parameter name for the code_challenge_method parameter. (RFC7636)
	CodeChallengeMethodParam = "code_challenge_method"
	// CodeVerifierParam is the parameter name for the code_verifier parameter. (RFC7636)
	CodeVerifierParam = "code_verifier"
	// GrantTypeParam is the parameter name for the grant_type parameter. (RFC6749)
	GrantTypeParam = "grant_type"
	// NonceParam is the parameter name for the nonce parameter
	NonceParam = "nonce"
	// PresentationDefParam is the parameter name for the OpenID4VP presentation_definition parameter. (OpenID4VP)
	PresentationDefParam = "presentation_definition"
	// PresentationDefUriParam is the parameter name for the OpenID4VP presentation_definition_uri parameter. (OpenID4VP)
	PresentationDefUriParam = "presentation_definition_uri"
	// PresentationSubmissionParam is the parameter name for the presentation_submission parameter. (OpenID4VP)
	PresentationSubmissionParam = "presentation_submission"
	// RedirectURIParam is the parameter name for the redirect_uri parameter. (RFC6749)
	RedirectURIParam = "redirect_uri"
	// RequestParam is the parameter name for the request parameter.	(RFC9101)
	RequestParam = "request"
	// RequestURIParam is the parameter name for the request parameter. (RFC9101)
	RequestURIParam = "request_uri"
	// RequestURIMethodParam states what http method (get/post) should be used for RequestURIParam. (OpenID4VP)
	RequestURIMethodParam = "request_uri_method"
	// ResponseModeParam is the parameter name for the OAuth2 response_mode parameter.
	ResponseModeParam = "response_mode"
	// ResponseTypeParam is the parameter name for the response_type parameter. (RFC6749)
	ResponseTypeParam = "response_type"
	// ResponseURIParam is the parameter name for the OpenID4VP response_uri parameter.
	ResponseURIParam = "response_uri"
	// ScopeParam is the parameter name for the scope parameter. (RFC6749)
	ScopeParam = "scope"
	// StateParam is the parameter name for the state parameter. (RFC6749)
	StateParam = "state"
	// VpTokenParam is the parameter name for the vp_token parameter. (OpenID4VP)
	VpTokenParam = "vp_token"
	// WalletMetadataParam is used by the wallet to provide its metadata in an authorization request when RequestURIMethodParam is 'post'
	WalletMetadataParam = "wallet_metadata"
	// WalletNonceParam is a wallet generated nonce to prevent authorization request replay when RequestURIMethodParam is 'post'
	WalletNonceParam = "wallet_nonce"
)

// grant types
const (
	// AuthorizationCodeGrantType is the grant_type for the authorization_code grant type. (RFC6749)
	AuthorizationCodeGrantType = "authorization_code"
	// PreAuthorizedCodeGrantType is the grant_type for the pre-authorized_code grant type. (OpenID4VCI)
	PreAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	// VpTokenGrantType is the grant_type for the vp_token-bearer grant type. (RFC021)
	VpTokenGrantType = "vp_token-bearer"
)

// response types
const (
	// CodeResponseType is the parameter name for the code parameter. (RFC6749)
	CodeResponseType = "code"
	// VPTokenResponseType is paramter name for the vp_token repsponse type. (OpenID4VP)
	VPTokenResponseType = "vp_token"
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
	Issuer string `json:"issuer,omitempty"`

	/* ******** /authorize ******** */

	// AuthorizationEndpoint defines the URL of the authorization server's authorization endpoint [RFC6749]
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`

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
	TokenEndpoint string `json:"token_endpoint,omitempty"`

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

	// VPFormatsSupported is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Wallet.
	VPFormatsSupported map[string]map[string][]string `json:"vp_formats_supported,omitempty"`

	// VPFormats is an object containing a list of key value pairs, where the key is a string identifying a Credential format supported by the Verifier.
	// TODO: Remove. VPFormatsSupported is the correct param, but the OpenID4VP spec is ambiguous so support both for now.
	VPFormats map[string]map[string][]string `json:"vp_formats,omitempty"`

	// ClientIdSchemesSupported defines the `client_id_schemes` currently supported.
	// If omitted, the default value is `pre-registered` (referring to the client), which is currently not supported.
	ClientIdSchemesSupported []string `json:"client_id_schemes_supported,omitempty"`

	// DIDMethodsSupported is a JSON array containing a list of the DID Methods (without scheme 'did:') that are supported by the Authorization Server.
	// Note: this is a custom parameter, not part of the OpenID4VC specifications.
	DIDMethodsSupported []string `json:"did_methods_supported,omitempty"`

	// DPoPSigningAlgValuesSupported is a JSON array containing a list of the DPoP proof JWS signing algorithms ("alg" values) supported by the token endpoint.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	/* ******** JWT-Secured Authorization Request RFC9101 & OpenID Connect Core v1.0: §6. Passing Request Parameters as JWTs ******** */

	// RequireSignedRequestObject specifies if the authorization server requires the use of signed request objects.
	RequireSignedRequestObject bool `json:"require_signed_request_object,omitempty"`

	// RequestObjectSigningAlgValuesSupported is a JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
	// These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
}

// SupportsClientIDScheme checks if the Authorization Server supports the given client ID scheme.
func (m AuthorizationServerMetadata) SupportsClientIDScheme(scheme string) bool {
	for _, method := range m.ClientIdSchemesSupported {
		if method == scheme {
			return true
		}
	}
	return false
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

// OpenIDCredentialIssuerMetadata represents the metadata of an OpenID credential issuer
type OpenIDCredentialIssuerMetadata struct {
	// - CredentialIssuer: an url representing the credential issuer
	CredentialIssuer string `json:"credential_issuer"`
	// - CredentialEndpoint: an url representing the credential endpoint
	CredentialEndpoint string `json:"credential_endpoint"`
	// - AuthorizationServers: a slice of urls representing the authorization servers (optional)
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// - Display: a slice of maps where each map represents the display information (optional)
	Display []map[string]string `json:"display,omitempty"`
}

// OpenIDConfiguration represents the OpenID configuration
// It contains the minimal information required for OpenID4VP, the required `jwks` is also omitted
// see https://openid.net/specs/openid-connect-federation-1_0-29.html#entity-statement
type OpenIDConfiguration struct {
	// Issuer: an url representing the issuer of the entity statement
	// for now we keep it teh same as the subject, eg the subject/tenant
	Issuer string `json:"iss"`
	// Subject: an url representing the subject of the entity statement
	Subject string `json:"sub"`
	// IssuedAt: the time the entity statement was issued
	IssuedAt int64 `json:"iat"`
	// JWKs is the JSON Web Key Set of the entity statement. Contains keys of all DIDs for the subject
	JWKs jwk.Set `json:"jwks"`
	// Metadata: the metadata of the entity statement
	Metadata EntityStatementMetadata `json:"metadata"`
}

// EntityStatementMetadata represents the metadata of an openID federation entity statement
// We only use the OpenID provider metadata
type EntityStatementMetadata struct {
	// OpenIDProvider: the metadata of the OpenID provider
	OpenIDProvider AuthorizationServerMetadata `json:"openid_provider"`
}

// UnmarshalJSON parses the OpenIDConfiguration from JSON
func (j *OpenIDConfiguration) UnmarshalJSON(bytes []byte) error {
	claims := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &claims); err != nil {
		return err
	}
	if issuer, ok := claims["iss"].(string); ok {
		j.Issuer = issuer
	}
	if subject, ok := claims["sub"].(string); ok {
		j.Subject = subject
	}
	if issuedAt, ok := claims["iat"].(float64); ok {
		j.IssuedAt = int64(issuedAt)
	}

	metadataJson, _ := json.Marshal(claims["metadata"])
	if err := json.Unmarshal(metadataJson, &j.Metadata); err != nil {
		return err
	}
	keysAsJson, _ := json.Marshal(claims["jwks"])
	j.JWKs = jwk.NewSet()

	return json.Unmarshal(keysAsJson, &j.JWKs)
}
