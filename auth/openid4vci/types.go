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
)

// JWTTypeOpenID4VCIProof is the JWT typ claim value used in OpenID4VCI key
// proofs (Appendix F.1).
const JWTTypeOpenID4VCIProof = "openid4vci-proof+jwt"

// OpenIDCredentialIssuerMetadata describes the OpenID4VCI Credential Issuer
// Metadata document published at /.well-known/openid-credential-issuer
// (Section 12.2). The document is OpenID4VCI-defined; it is not an OAuth
// authorization-server metadata document.
type OpenIDCredentialIssuerMetadata struct {
	CredentialIssuer     string              `json:"credential_issuer"`
	CredentialEndpoint   string              `json:"credential_endpoint"`
	NonceEndpoint        string              `json:"nonce_endpoint,omitempty"`
	AuthorizationServers []string            `json:"authorization_servers,omitempty"`
	Display              []map[string]string `json:"display,omitempty"`
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
