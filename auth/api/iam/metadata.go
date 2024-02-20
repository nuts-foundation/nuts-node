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
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
	"strings"
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

func authorizationServerMetadata(identity url.URL) oauth.AuthorizationServerMetadata {
	return oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:    identity.JoinPath("authorize").String(),
		ClientIdSchemesSupported: clientIdSchemesSupported,
		GrantTypesSupported:      grantTypesSupported,
		Issuer:                   identity.String(),
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionEndpoint:             identity.JoinPath("presentation_definition").String(),
		RequireSignedRequestObject:                 true,
		ResponseModesSupported:                     responseModesSupported,
		ResponseTypesSupported:                     responseTypesSupported,
		TokenEndpoint:                              identity.JoinPath("token").String(),
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
	}
}

// clientMetadata should only be used for dids managed by the node. It assumes the provided identity URL is correct.
func clientMetadata(identity url.URL) OAuthClientMetadata {
	softwareID, softwareVersion, _ := strings.Cut(core.UserAgent(), "/")
	return OAuthClientMetadata{
		//RedirectURIs:            nil,
		TokenEndpointAuthMethod: "none", // defaults is "client_secret_basic" if not provided
		GrantTypes:              grantTypesSupported,
		ResponseTypes:           responseTypesSupported,
		//Scope:                   "",
		//Contacts:                nil,
		//JwksURI:                 "",
		//Jwks:                    nil,
		SoftwareID:      softwareID,      // nuts-node-refimpl
		SoftwareVersion: softwareVersion, // version tag or "unknown"
		//CredentialOfferEndpoint: "",
		VPFormats:      oauth.DefaultOpenIDSupportedFormats(),
		ClientIdScheme: "did",
	}
}
