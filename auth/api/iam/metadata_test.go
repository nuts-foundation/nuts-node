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
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func Test_authorizationServerMetadata(t *testing.T) {
	identity := "https://example.com/iam/did:nuts:123"
	identityURL, _ := url.Parse(identity)
	expected := oauth.AuthorizationServerMetadata{
		Issuer:                 identity,
		AuthorizationEndpoint:  identity + "/authorize",
		ResponseTypesSupported: []string{"code", "vp_token", "vp_token id_token"},
		ResponseModesSupported: []string{"query", "direct_post"},
		TokenEndpoint:          identity + "/token",
		GrantTypesSupported:    []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionEndpoint:             identity + "/presentation_definition",
		RequireSignedRequestObject:                 true,
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
		ClientIdSchemesSupported:                   []string{"did"},
	}
	assert.Equal(t, expected, authorizationServerMetadata(*identityURL))
}

func Test_clientMetadata(t *testing.T) {
	core.GitVersion = "testVersion"
	expected := OAuthClientMetadata{
		RedirectURIs:            nil,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		ResponseTypes:           []string{"code", "vp_token", "vp_token id_token"},
		Scope:                   "",
		Contacts:                nil,
		JwksURI:                 "",
		Jwks:                    nil,
		SoftwareID:              "nuts-node-refimpl",
		SoftwareVersion:         "testVersion",
		CredentialOfferEndpoint: "",
		VPFormats:               oauth.DefaultOpenIDSupportedFormats(),
		ClientIdScheme:          "did",
	}
	assert.Equal(t, expected, clientMetadata(url.URL{}))
}
