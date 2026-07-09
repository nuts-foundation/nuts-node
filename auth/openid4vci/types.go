/*
 * Nuts node
 * Copyright (C) 2026 Nuts community
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

// Package openid4vci implements the OpenID for Verifiable Credential Issuance
// 1.0 (ID-1) protocol surface used by the user/browser flow in auth/api/iam.
//
// This package owns the v1.0 protocol types, error codes, and the HTTP client
// used to talk to a Credential Issuer. Consumers in auth/api/iam (HTTP
// handlers) and auth/client/iam (low-level HTTP plumbing) import from here.
//
// This package is independent of vcr/openid4vci, which is an internal
// node-to-node draft-11 issuance flow that diverges from v1.0 in several
// material ways and is not consumed from auth/.
//
// Reference: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
package openid4vci

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
)

// JWTTypeOpenID4VCIProof is the JWT typ claim value used in OpenID4VCI key
// proofs (Appendix F.1).
const JWTTypeOpenID4VCIProof = "openid4vci-proof+jwt"

// AuthorizationDetailsTypeOpenIDCredential is the RFC 9396 authorization_details
// "type" value used for OpenID4VCI credential issuance (§5.1.1).
const AuthorizationDetailsTypeOpenIDCredential = "openid_credential"

// OpenIDCredentialIssuerMetadata describes the OpenID4VCI Credential Issuer
// Metadata document published at /.well-known/openid-credential-issuer
// (Section 12.2). The document is OpenID4VCI-defined; it is not an OAuth
// authorization-server metadata document.
type OpenIDCredentialIssuerMetadata struct {
	CredentialIssuer                  string                             `json:"credential_issuer"`
	CredentialEndpoint                string                             `json:"credential_endpoint"`
	NonceEndpoint                     string                             `json:"nonce_endpoint,omitempty"`
	AuthorizationServers              []string                           `json:"authorization_servers,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
}

// CredentialConfiguration is one entry of credential_configurations_supported
// in the Credential Issuer Metadata (§12.2). Only the fields needed to resolve
// a credential_type to a credential_configuration_id are modeled: the
// type-locating field depends on the format (CredentialDefinition.Type for
// jwt_vc_json/ldp_vc, Vct for vc+sd-jwt/dc+sd-jwt).
type CredentialConfiguration struct {
	Format               string                `json:"format"`
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
	Vct                  string                `json:"vct,omitempty"`
}

// MatchesType checks whether this credential_configurations_supported entry is of the given
// credential type, using the type-locating field per format (§12.2): credential_definition.type
// (jwt_vc_json, ldp_vc; ignoring the base "VerifiableCredential" entry) or vct (vc+sd-jwt,
// dc+sd-jwt). vct is still matched here, even though the node doesn't support those formats
// (oauth.DefaultOpenIDSupportedFormats), so such entries produce the more useful "only offered in
// unsupported format(s)" error instead of "does not offer this type at all".
func (c CredentialConfiguration) MatchesType(credentialType string) bool {
	if credentialType == "VerifiableCredential" {
		return false
	}
	if c.CredentialDefinition != nil && slices.Contains(c.CredentialDefinition.Type, credentialType) {
		return true
	}
	return c.Vct != "" && c.Vct == credentialType
}

// CredentialDefinition carries the credential type array used by the
// jwt_vc_json and ldp_vc formats.
type CredentialDefinition struct {
	Type []string `json:"type"`
}

// AuthorizationDetail is a single authorization_details entry (RFC 9396) sent
// on the Authorization Request when the Authorization Server supports the
// openid_credential type (§5.1.1).
type AuthorizationDetail struct {
	Type                      string `json:"type"`
	CredentialConfigurationID string `json:"credential_configuration_id"`
}

// GetIssuer returns the credential issuer identifier, for metadata discovery
// validation (see oauth.FetchMetadata).
func (m OpenIDCredentialIssuerMetadata) GetIssuer() string {
	return m.CredentialIssuer
}

// WellKnownPath returns the well-known path under which the Credential Issuer Metadata is
// published (§12.2), used by oauth.FetchMetadata to derive the metadata URL.
func (m OpenIDCredentialIssuerMetadata) WellKnownPath() string {
	return oauth.OpenIdCredIssuerWellKnown
}

// ResolveCredentialConfigurationID matches credentialType against
// CredentialConfigurationsSupported (§12.2) and returns the matching credential_configuration_id.
// Matching is done on the type-locating field, not the map key: the spec lets
// credential_configuration_id be an arbitrary issuer-chosen string.
//
//   - 0 matches: the issuer does not offer this credential type at all.
//   - matches only in formats the node does not support (oauth.DefaultOpenIDSupportedFormats): the
//     type exists, but the node cannot request it.
//   - 1+ matches in a supported format: candidate IDs are sorted so the pick is deterministic
//     (never Go map order); the smallest ID wins.
func (m OpenIDCredentialIssuerMetadata) ResolveCredentialConfigurationID(credentialType string) (string, error) {
	type candidate struct {
		id     string
		format string
	}
	var matches []candidate
	for id, config := range m.CredentialConfigurationsSupported {
		if config.MatchesType(credentialType) {
			matches = append(matches, candidate{id: id, format: config.Format})
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("issuer does not offer a credential of type %q", credentialType)
	}
	supportedFormats := oauth.DefaultOpenIDSupportedFormats()
	var supportedMatches []candidate
	for _, c := range matches {
		if _, ok := supportedFormats[c.format]; ok {
			supportedMatches = append(supportedMatches, c)
		}
	}
	if len(supportedMatches) == 0 {
		unsupportedFormats := make([]string, len(matches))
		for i, c := range matches {
			unsupportedFormats[i] = c.format
		}
		sort.Strings(unsupportedFormats)
		unsupportedFormats = slices.Compact(unsupportedFormats)
		return "", fmt.Errorf("issuer offers %q only in format(s): %s", credentialType, strings.Join(unsupportedFormats, ", "))
	}
	sort.Slice(supportedMatches, func(i, j int) bool { return supportedMatches[i].id < supportedMatches[j].id })
	return supportedMatches[0].id, nil
}

// NonceResponse is the body returned by the Nonce Endpoint (Section 7.2).
type NonceResponse struct {
	CNonce string `json:"c_nonce"`
}

// CredentialRequest is the body of a Credential Request (Section 8.2).
//
// Either CredentialConfigurationID or CredentialIdentifier identifies the
// requested credential — see §5.1.1: when the Token Response carried
// authorization_details with credential_identifiers, the wallet sends
// CredentialIdentifier; otherwise it sends CredentialConfigurationID.
// Today the auth-side flow only emits CredentialConfigurationID; the field
// for CredentialIdentifier is present so future support is non-breaking.
type CredentialRequest struct {
	CredentialConfigurationID string                   `json:"credential_configuration_id,omitempty"`
	CredentialIdentifier      string                   `json:"credential_identifier,omitempty"`
	Proofs                    *CredentialRequestProofs `json:"proofs,omitempty"`
}

// CredentialRequestProofs carries one or more key proofs in a Credential
// Request (the proofs parameter defined in Section 8.2; proof type formats
// are listed in Appendix F).
type CredentialRequestProofs struct {
	JWT []string `json:"jwt,omitempty"`
}

// CredentialResponse is the body returned by the Credential Endpoint
// (Section 8.3).
//
// TransactionID, Interval, and NotificationID are present for forward
// compatibility (deferred issuance via HTTP 202 with a transaction id, and
// notification ids consumed by the Notification Endpoint in §11). The
// auth-side flow today consumes only Credentials; the other fields are
// populated when the issuer sends them so they are available without a
// wire-format change later.
type CredentialResponse struct {
	Credentials    []CredentialResponseEntry `json:"credentials,omitempty"`
	TransactionID  string                    `json:"transaction_id,omitempty"`
	Interval       int                       `json:"interval,omitempty"`
	NotificationID string                    `json:"notification_id,omitempty"`
}

// CredentialResponseEntry is one issued credential in a Credential Response.
type CredentialResponseEntry struct {
	Credential json.RawMessage `json:"credential"`
}
