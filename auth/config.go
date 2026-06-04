/*
 * Copyright (C) 2021 Nuts community
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

package auth

import (
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned"
)

// Config holds all the configuration params
type Config struct {
	Irma                  IrmaConfig                  `koanf:"irma"`
	HTTPTimeout           int                         `koanf:"http.timeout"`
	ClockSkew             int                         `koanf:"clockskew"`
	ContractValidators    []string                    `koanf:"contractvalidators"`
	AccessTokenLifeSpan   int                         `koanf:"accesstokenlifespan"`
	AuthorizationEndpoint AuthorizationEndpointConfig `koanf:"authorizationendpoint"`
	// GrantTypes lists OAuth2 grant types the Authorization Server supports.
	// They will be advertised on the Authorization Server Metadata and be checked when an access token request comes in.
	GrantTypes   []string           `koanf:"granttypes"`
	Experimental ExperimentalConfig `koanf:"experimental"`
}

// ExperimentalConfig groups feature flags for unstable functionality.
// Anything inside is subject to change without notice and may be removed in a future release.
type ExperimentalConfig struct {
	// JwtBearerClient enables the RFC 7523 jwt-bearer two-VP token request flow.
	// While disabled (the default), requests carrying a service-provider subject identifier are rejected.
	JwtBearerClient bool `koanf:"jwtbearerclient"`
	// Clients configures OAuth client authentication for outbound flows against external authorization servers
	// (currently only the OpenID4VCI authorization code flow). When the node initiates a flow against an
	// authorization server whose identifier matches an entry's ServerURL, it presents the configured client_id
	// (and client_secret, if set) instead of the did:web + entity_id defaults.
	//
	// EXPERIMENTAL: this configuration may change or be removed without further notice.
	Clients []OAuthClientConfig `koanf:"clients"`
}

// OAuthClientConfig holds client credentials the node presents to a specific external OAuth authorization server.
//
// EXPERIMENTAL: this configuration may change or be removed without further notice.
type OAuthClientConfig struct {
	// ServerURL is the OAuth Authorization Server identifier (issuer) to match against. For OpenID4VCI this is
	// the entry from the Credential Issuer Metadata's authorization_servers, not the credential_issuer URL.
	ServerURL string `koanf:"serverurl"`
	// ClientID is the client identifier registered at the authorization server.
	ClientID string `koanf:"clientid"`
	// ClientSecret authenticates the client at the token endpoint using client_secret_post. Optional: when empty
	// the node acts as a public client (relying on PKCE).
	ClientSecret string `koanf:"clientsecret"`
}

type AuthorizationEndpointConfig struct {
	// Enabled is a flag to enable or disable the v2 API's Authorization Endpoint (/authorize), used for:
	// - As OpenID4VP verifier: to authenticate clients (that initiate the Authorized Code flow) using OpenID4VP
	// - As OpenID4VP wallet: to authenticate verifiers using OpenID4VP
	// - As OpenID4VCI wallet: to support dynamic credential requests (currently not supported)
	// Disabling the authorization endpoint will also disable to callback endpoint and removes the endpoint from the metadata.
	Enabled bool `koanf:"enabled"`
}

type IrmaConfig struct {
	SchemeManager     string     `koanf:"schememanager"`
	AutoUpdateSchemas bool       `koanf:"autoupdateschemas"`
	CORS              CORSConfig `koanf:"cors"`
}

// CORSConfig contains configuration for Cross Origin Resource Sharing.
type CORSConfig struct {
	// Origin specifies the AllowOrigin option. If no origins are given CORS is considered to be disabled.
	Origin []string `koanf:"origin"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		Irma: IrmaConfig{
			SchemeManager:     "pbdf",
			AutoUpdateSchemas: true,
		},
		ClockSkew: 5000,
		ContractValidators: []string{
			string(services.IrmaFormat),
			dummy.ContractFormat,
			selfsigned.ContractFormat,
		},
		AccessTokenLifeSpan: 60, // seconds, as specced in RFC003
		GrantTypes: []string{
			oauth.AuthorizationCodeGrantType,
			oauth.VpTokenGrantType,
			oauth.JwtBearerGrantType,
		},
	}
}
