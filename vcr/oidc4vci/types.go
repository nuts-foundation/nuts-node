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

// This file defines types specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

package oidc4vci

import (
	"crypto/tls"
	"time"
)

// PreAuthorizedCodeGrant is the grant type used for pre-authorized code grant from the OIDC4VCI specification.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow
const PreAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// ProviderMetadataWellKnownPath defines the well-known path for retrieving OpenID ProviderMetadata
// Specified by https://www.rfc-editor.org/rfc/rfc8414.html#section-3
const ProviderMetadataWellKnownPath = "/.well-known/oauth-authorization-server"

// CredentialIssuerMetadataWellKnownPath defines the well-known path for retrieving OIDC4VCI CredentialIssuerMetadata
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-
const CredentialIssuerMetadataWellKnownPath = "/.well-known/openid-credential-issuer"

// VerifiableCredentialJSONLDFormat defines the JSON-LD format identifier for Verifiable Credentials.
const VerifiableCredentialJSONLDFormat = "ldp_vc"

// JWTTypeOpenID4VCIProof defines the OpenID4VCI JWT-subtype (used as typ claim in the JWT).
const JWTTypeOpenID4VCIProof = "openid4vci-proof+jwt"

// ProofTypeJWT defines the Credential Request proof type for JWTs.
const ProofTypeJWT = "jwt"

// CredentialOfferStatus defines the status of a credential offer flow.
type CredentialOfferStatus string

// CredentialOfferStatusReceived indicates that the wallet has received the credential.
const CredentialOfferStatusReceived CredentialOfferStatus = "credential_received"

// CredentialIssuerMetadata defines the OIDC4VCI Credential Issuer Metadata.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
type CredentialIssuerMetadata struct {
	// CredentialIssuer defines the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialEndpoint defines where the wallet can send a request to retrieve a credential.
	CredentialEndpoint string `json:"credential_endpoint"`

	// CredentialsSupported defines metadata about which credential types the credential issuer can issue.
	CredentialsSupported []map[string]interface{} `json:"credentials_supported"`
}

// OAuth2ClientMetadata defines the OAuth2 Client Metadata, extended with OIDC4VCI parameters.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata.
type OAuth2ClientMetadata struct {
	// CredentialOfferEndpoint defines URL of the verifiable credential wallet's offer endpoint
	CredentialOfferEndpoint string `json:"credential_offer_endpoint"`
}

// ProviderMetadata defines the OpenID Connect Provider metadata.
// Specified by https://www.rfc-editor.org/rfc/rfc8414.txt
type ProviderMetadata struct {
	// Issuer defines the authorization server's identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	Issuer string `json:"issuer"`

	// TokenEndpoint defines the URL of the authorization server's token endpoint [RFC6749].
	TokenEndpoint string `json:"token_endpoint"`

	// PreAuthorizedGrantAnonymousAccessSupported indicates whether anonymous access (requests without client_id)
	// for pre-authorized code grant flows.
	// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported"`
}

// CredentialOffer defines credentials offered by the issuer to the wallet.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
type CredentialOffer struct {
	// CredentialIssuer defines the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`
	// Credentials defines the credentials offered by the issuer to the wallet.
	Credentials []map[string]interface{} `json:"credentials"`
	// Grants defines the grants offered by the issuer to the wallet.
	Grants map[string]interface{} `json:"grants"`
}

// CredentialOfferResponse defines the response for credential offer requests.
// It is an extension to the OIDC4VCI specification to better support server-to-server issuance.
type CredentialOfferResponse struct {
	// Status defines the status of the credential offer.
	Status CredentialOfferStatus `json:"status"`
}

// CredentialRequest defines the credential request sent by the wallet to the issuer.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request.
type CredentialRequest struct {
	Format               string                  `json:"format"`
	CredentialDefinition *map[string]interface{} `json:"credential_definition,omitempty"`
	Proof                *CredentialRequestProof `json:"proof,omitempty"`
}

// CredentialRequestProof defines the proof of possession of key material when requesting a Credential.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
type CredentialRequestProof struct {
	Jwt       string `json:"jwt"`
	ProofType string `json:"proof_type"`
}

// CredentialResponse defines the response for credential requests.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialResponse struct {
	Format     string                  `json:"format,omitempty"`
	Credential *map[string]interface{} `json:"credential,omitempty"`
	CNonce     *string                 `json:"c_nonce,omitempty"`
}

// TokenResponse defines the response for OAuth2 access token requests, extended with OIDC4VCI parameters.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response
type TokenResponse struct {
	// AccessToken defines the access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// CNonce defines the JSON string containing a nonce to be used to create a proof of possession of key material when requesting a Credential. When received, the WalletAPIClient MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.
	CNonce *string `json:"c_nonce,omitempty"`

	// ExpiresIn defines the lifetime in seconds of the access token.
	ExpiresIn *int `json:"expires_in,omitempty"`

	// TokenType defines the type of the token issued as described in [RFC6749].
	TokenType string `json:"token_type"`
}

// Config holds the config for the OIDC4VCI credential issuer and wallet
type Config struct {
	// DefinitionsDIR defines the directory where the credential definitions are stored
	DefinitionsDIR string `koanf:"definitionsdir"`
	// Enabled indicates if issuing and receiving credentials over OIDC4VCI is enabled
	Enabled bool `koanf:"enabled"`
	// URL defines the base URL of the OIDC4VCI issuer and wallet
	URL string `koanf:"url"`
	// Timeout defines the timeout for HTTP client operations
	Timeout time.Duration `koanf:"timeout"`
}

// ClientConfig holds openid4vci client configuration
type ClientConfig struct {
	Timeout   time.Duration
	TLS       *tls.Config
	HTTPSOnly bool
}
