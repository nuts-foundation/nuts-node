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
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"net/url"
	"strings"
)

func authorizationServerMetadata(identity url.URL, oauth2BaseURL url.URL) oauth.AuthorizationServerMetadata {
	return oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      oauth2BaseURL.JoinPath("authorize").String(),
		ClientIdSchemesSupported:                   clientIdSchemesSupported,
		DPoPSigningAlgValuesSupported:              dpop.SigningAlgValuesSupported,
		GrantTypesSupported:                        grantTypesSupported,
		Issuer:                                     identity.String(),
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionEndpoint:             oauth2BaseURL.JoinPath("presentation_definition").String(),
		RequireSignedRequestObject:                 true,
		ResponseModesSupported:                     responseModesSupported,
		ResponseTypesSupported:                     responseTypesSupported,
		TokenEndpoint:                              oauth2BaseURL.JoinPath("token").String(),
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
