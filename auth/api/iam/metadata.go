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

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
)

func authorizationServerMetadata(issuerURL *url.URL, supportedDIDMethods []string) oauth.AuthorizationServerMetadata {
	metadata := &oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      "openid4vp:",
		ClientIdSchemesSupported:                   clientIdSchemesSupported,
		DIDMethodsSupported:                        supportedDIDMethods,
		DPoPSigningAlgValuesSupported:              jwx.SupportedAlgorithmsAsStrings(),
		GrantTypesSupported:                        grantTypesSupported,
		Issuer:                                     issuerURL.String(),
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionUriSupported:         to.Ptr(true),
		RequireSignedRequestObject:                 true,
		ResponseModesSupported:                     responseModesSupported,
		ResponseTypesSupported:                     responseTypesSupported,
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
		RequestObjectSigningAlgValuesSupported:     jwx.SupportedAlgorithmsAsStrings(),
	}

	metadata.AuthorizationEndpoint = issuerURL.JoinPath("authorize").String()
	metadata.PresentationDefinitionEndpoint = issuerURL.JoinPath("presentation_definition").String()
	metadata.TokenEndpoint = issuerURL.JoinPath("token").String()
	return *metadata
}

// staticAuthorizationServerMetadata is used in the OpenID4VP flow when authorization server (wallet) issuer is unknown.
// Note: several specs (OpenID4VP, SIOPv2, OpenID core) define a static authorization server configuration that currently are conflicting.
func staticAuthorizationServerMetadata() oauth.AuthorizationServerMetadata {
	return oauth.AuthorizationServerMetadata{
		Issuer:                   "https://self-issued.me/v2",
		AuthorizationEndpoint:    "openid4vp:",
		ClientIdSchemesSupported: clientIdSchemesSupported,
		ResponseTypesSupported:   []string{oauth.VPTokenResponseType},
		VPFormatsSupported: map[string]map[string][]string{
			"jwt_vp_json": {"alg_values_supported": []string{string(jwa.ES256)}},
			"jwt_vc_json": {"alg_values_supported": []string{string(jwa.ES256)}},
		},
		RequestObjectSigningAlgValuesSupported: []string{string(jwa.ES256)},
	}
}

// clientMetadata should only be used for dids managed by the node. It assumes the provided identity URL is correct.
func clientMetadata(identity url.URL) oauth.OAuthClientMetadata {
	softwareID, softwareVersion, _ := strings.Cut(core.UserAgent(), "/")
	return oauth.OAuthClientMetadata{
		TokenEndpointAuthMethod: "none", // defaults is "client_secret_basic" if not provided
		GrantTypes:              grantTypesSupported,
		ResponseTypes:           responseTypesSupported,
		SoftwareID:              softwareID,      // nuts-node-refimpl
		SoftwareVersion:         softwareVersion, // version tag or "unknown"
		VPFormats:               oauth.DefaultOpenIDSupportedFormats(),
		ClientIdScheme:          entityClientIDScheme,
	}
}

func openIDConfiguration(issuerURL url.URL, jwkSet jwk.Set, supportedDIDMethods []string) oauth.OpenIDConfiguration {
	return oauth.OpenIDConfiguration{
		Issuer:         issuerURL.String(),
		IssuedAt:       time.Now().Unix(),
		Subject:        issuerURL.String(),
		JWKs:           jwkSet,
		OpenIDProvider: authorizationServerMetadata(&issuerURL, supportedDIDMethods),
	}
}
