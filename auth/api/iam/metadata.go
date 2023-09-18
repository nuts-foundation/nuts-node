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
	"github.com/nuts-foundation/nuts-node/core"
	"net/url"
	"strings"
)

const (
	// authzServerWellKnown is the well-known base path for the oauth authorization server metadata as defined in RFC8414
	authzServerWellKnown = "/.well-known/oauth-authorization-server"
	// openidCredIssuerWellKnown is the well-known base path for the openID credential issuer metadata as defined in OpenID4VCI specification
	openidCredIssuerWellKnown = "/.well-known/openid-credential-issuer"
	// openidCredWalletWellKnown is the well-known path element we created for openid4vci to retrieve the oauth client metadata
	openidCredWalletWellKnown = "/.well-known/openid-credential-wallet"
)

// IssuerIdToWellKnown converts the OAuth2 Issuer identity to the specified well-known endpoint by inserting the well-known at the root of the path.
// It returns no url and an error when issuer is not a valid URL.
func IssuerIdToWellKnown(issuer string, wellKnown string, strictmode bool) (*url.URL, error) {
	var issuerURL *url.URL
	var err error
	if strictmode {
		issuerURL, err = core.ParsePublicURL(issuer, false, "https")
	} else {
		issuerURL, err = core.ParsePublicURL(issuer, true, "https", "http")
	}
	if err != nil {
		return nil, err
	}
	return issuerURL.Parse(wellKnown + issuerURL.EscapedPath())
}

func authorizationServerMetadata(identity url.URL) OAuthAuthorizationServerMetadata {
	return OAuthAuthorizationServerMetadata{
		Issuer:                 identity.String(),
		AuthorizationEndpoint:  identity.JoinPath("authorize").String(),
		ResponseTypesSupported: responseTypesSupported,
		ResponseModesSupported: responseModesSupported,
		TokenEndpoint:          identity.JoinPath("token").String(),
		GrantTypesSupported:    grantTypesSupported,
		PreAuthorizedGrantAnonymousAccessSupported: true,
		VPFormats:                vpFormatsSupported,
		VPFormatsSupported:       vpFormatsSupported,
		ClientIdSchemesSupported: clientIdSchemesSupported,
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
		VPFormats:      vpFormatsSupported,
		ClientIdScheme: "did",
	}
}
