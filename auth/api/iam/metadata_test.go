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
	"net/url"
	"testing"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
)

func Test_authorizationServerMetadata(t *testing.T) {
	presentationDefinitionURISupported := true
	baseExpected := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      "https://example.com/oauth2/example/authorize",
		TokenEndpoint:                              "https://example.com/oauth2/example/token",
		ClientIdSchemesSupported:                   []string{"entity_id"},
		DIDMethodsSupported:                        []string{"test"},
		DPoPSigningAlgValuesSupported:              jwx.SupportedAlgorithmsAsStrings(),
		GrantTypesSupported:                        []string{"authorization_code", "vp_token-bearer"},
		Issuer:                                     "https://example.com/oauth2/example",
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionEndpoint:             "https://example.com/oauth2/example/presentation_definition",
		PresentationDefinitionUriSupported:         &presentationDefinitionURISupported,
		RequireSignedRequestObject:                 true,
		ResponseTypesSupported:                     []string{"code", "vp_token"},
		ResponseModesSupported:                     []string{"query", "direct_post"},
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
		RequestObjectSigningAlgValuesSupported:     jwx.SupportedAlgorithmsAsStrings(),
	}
	authServerUrl := test.MustParseURL("https://example.com/oauth2/example")
	md := authorizationServerMetadata(authServerUrl, []string{"test"})
	assert.Equal(t, baseExpected, md)
}

func Test_clientMetadata(t *testing.T) {
	core.GitVersion = "testVersion"
	expected := OAuthClientMetadata{
		RedirectURIs:            nil,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "vp_token-bearer"},
		ResponseTypes:           []string{"code", "vp_token"},
		Scope:                   "",
		Contacts:                nil,
		JwksURI:                 "",
		Jwks:                    nil,
		SoftwareID:              "nuts-node-refimpl",
		SoftwareVersion:         "testVersion",
		CredentialOfferEndpoint: "",
		VPFormats:               oauth.DefaultOpenIDSupportedFormats(),
		ClientIdScheme:          "entity_id",
	}
	assert.Equal(t, expected, clientMetadata(url.URL{}))
}
