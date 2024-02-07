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

const (
	// OpenIdCredIssuerWellKnown is the well-known base path for the openID credential issuer metadata as defined in OpenID4VCI specification
	OpenIdCredIssuerWellKnown = "/.well-known/openid-credential-issuer"

	OpenIdConfigurationWellKnown = "/.well-known/openid-configuration"
)

type OpenIDCredentialIssuerMetadata struct {
	CredentialIssuer     string              `json:"credential_issuer"`
	CredentialEndpoint   string              `json:"credential_endpoint"`
	AuthorizationServers []string            `json:"authorization_servers,omitempty"`
	Display              []map[string]string `json:"display,omitempty"`
}

type OpenIDConfigurationMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JwksUri               string   `json:"jwks_uri"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
}

type Oid4vciTokenResponse struct {
	AccessToken          string  `json:"access_token"`
	ExpiresIn            *int    `json:"expires_in,omitempty"`
	TokenType            string  `json:"token_type"`
	CNonce               *string `json:"c_nonce,omitempty"`
	CNonceExpiresIn      *int    `json:"c_nonce_expires_in,omitempty"`
	Scope                *string `json:"scope,omitempty"`
	AuthorizationDetails *any    `json:"authorization_details,omitempty"`
}
