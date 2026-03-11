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

package openid4vci

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"time"
)

// PreAuthorizedCodeGrant is the grant type used for pre-authorized code grant from the OpenID4VCI specification.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow
const PreAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// WalletMetadataWellKnownPath defines the well-known path for OpenID4VCI Wallet Metadata.
// It is NOT specified by the OpenID4VCI specification, we just use it to be consistent with the other well-known paths.
const WalletMetadataWellKnownPath = "/.well-known/openid-credential-wallet"

// ProviderMetadataWellKnownPath defines the well-known path for retrieving OpenID ProviderMetadata
// Specified by https://www.rfc-editor.org/rfc/rfc8414.html#section-3
const ProviderMetadataWellKnownPath = "/.well-known/oauth-authorization-server"

// CredentialIssuerMetadataWellKnownPath defines the well-known path for retrieving OpenID4VCI CredentialIssuerMetadata
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-
const CredentialIssuerMetadataWellKnownPath = "/.well-known/openid-credential-issuer"

// JWTTypeOpenID4VCIProof defines the OpenID4VCI JWT-subtype (used as typ claim in the JWT).
const JWTTypeOpenID4VCIProof = "openid4vci-proof+jwt"

// ProofTypeJWT defines the Credential Request proof type for JWTs.
const ProofTypeJWT = "jwt"

// CredentialOfferStatus defines the status of a credential offer flow.
type CredentialOfferStatus string

// CredentialOfferStatusReceived indicates that the wallet has received the credential.
const CredentialOfferStatusReceived CredentialOfferStatus = "credential_received"

// CredentialIssuerMetadata defines the OpenID4VCI Credential Issuer Metadata.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
type CredentialIssuerMetadata struct {
	// CredentialIssuer defines the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialEndpoint defines where the wallet can send a request to retrieve a credential.
	CredentialEndpoint string `json:"credential_endpoint"`

	// NonceEndpoint defines the URL of the Nonce Endpoint where wallets can request a fresh c_nonce.
	// Per v1.0 Section 7, a Credential Issuer that requires c_nonce values MUST offer a Nonce Endpoint.
	NonceEndpoint string `json:"nonce_endpoint,omitempty"`

	// CredentialConfigurationsSupported defines metadata about which credential types the credential issuer can issue.
	// The map is keyed by credential_configuration_id.
	CredentialConfigurationsSupported map[string]map[string]interface{} `json:"credential_configurations_supported"`
}

// NonceResponse defines the response from the Nonce Endpoint.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
type NonceResponse struct {
	CNonce string `json:"c_nonce"`
}

// OAuth2ClientMetadata defines the OAuth2 Client Metadata, extended with OpenID4VCI parameters.
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
	// CredentialConfigurationIDs defines references to credential configurations offered by the issuer.
	// These IDs reference entries in the credential_configurations_supported metadata.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`
	// Grants defines the grants offered by the issuer to the wallet.
	Grants *CredentialOfferGrants `json:"grants,omitempty"`
}

// CredentialOfferGrants defines the grant types in a credential offer.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
type CredentialOfferGrants struct {
	PreAuthorizedCode *PreAuthorizedCodeParams `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// PreAuthorizedCodeParams defines the parameters for the pre-authorized code grant.
type PreAuthorizedCodeParams struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
}

// OfferedCredential represents a resolved credential configuration from issuer metadata.
// It is used internally by the holder to validate offered credentials after resolving a credential_configuration_id.
type OfferedCredential struct {
	// Format specifies the credential format.
	Format string `json:"format"`
	// CredentialDefinition contains the 'credential_definition' for the Verifiable Credential Format flows.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

// CredentialDefinition defines the 'credential_definition' for Format VerifiableCredentialJSONLDFormat
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html Appendix A.1.2
type CredentialDefinition struct {
	Context           []ssi.URI              `json:"@context"`
	Type              []ssi.URI              `json:"type"`
	CredentialSubject map[string]interface{} `json:"credentialSubject,omitempty"` // optional and currently not used
}

// CredentialOfferResponse defines the response for credential offer requests.
// It is an extension to the OpenID4VCI specification to better support server-to-server issuance.
type CredentialOfferResponse struct {
	// Status defines the status of the credential offer.
	Status CredentialOfferStatus `json:"status"`
}

// CredentialRequest defines the credential request sent by the wallet to the issuer.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
// Per v1.0 Section 8.2, the request identifies the credential using credential_configuration_id.
type CredentialRequest struct {
	// CredentialConfigurationID references a credential configuration from issuer metadata.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`
	// Proofs contains the proof(s) of possession of the key material.
	Proofs *CredentialRequestProofs `json:"proofs,omitempty"`
}

// CredentialRequestProofs defines the proof(s) of possession of key material when requesting a Credential.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
// The structure is: {"jwt": ["eyJ...", ...]} where the key is the proof type and the value is an array.
type CredentialRequestProofs struct {
	Jwt []string `json:"jwt"`
}

// CredentialResponse defines the response for credential requests.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
// In v1.0, when proofs (plural) is used in the request, the response uses `credentials` (array of wrapper objects).
// Each element contains a `credential` key holding the actual issued credential.
type CredentialResponse struct {
	Credentials []CredentialResponseEntry `json:"credentials,omitempty"`
}

// CredentialResponseEntry is a single entry in the credentials array of a CredentialResponse.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialResponseEntry struct {
	Credential json.RawMessage `json:"credential"`
}

// Config holds the config for the OpenID4VCI credential issuer and wallet
type Config struct {
	// DefinitionsDIR defines the directory where the additional credential definitions are stored
	DefinitionsDIR string `koanf:"definitionsdir"`
	// Enabled indicates if issuing and receiving credentials over OpenID4VCI is enabled
	Enabled bool `koanf:"enabled"`
	// Timeout defines the timeout for HTTP client operations
	Timeout time.Duration `koanf:"timeout"`
}
