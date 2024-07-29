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
		AuthorizationEndpoint:                      "https://example.com/oauth2/subby/authorize",
		TokenEndpoint:                              "https://example.com/oauth2/subby/token",
		PresentationDefinitionEndpoint:             "https://example.com/oauth2/subby/presentation_definition",
		ClientIdSchemesSupported:                   []string{"did"},
		DPoPSigningAlgValuesSupported:              jwx.SupportedAlgorithmsAsStrings(),
		GrantTypesSupported:                        []string{"authorization_code", "vp_token-bearer"},
		Issuer:                                     "https://example.com/oauth2/" + subjectID,
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionUriSupported:         &presentationDefinitionURISupported,
		RequireSignedRequestObject:                 true,
		ResponseTypesSupported:                     []string{"code", "vp_token"},
		ResponseModesSupported:                     []string{"query", "direct_post"},
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
		RequestObjectSigningAlgValuesSupported:     jwx.SupportedAlgorithmsAsStrings(),
	}
	t.Run("base", func(t *testing.T) {
		md := authorizationServerMetadata(test.MustParseURL("https://example.com/oauth2/" + subjectID))
		assert.Equal(t, baseExpected, md)
	})
	t.Run("did:web", func(t *testing.T) {
		issuerURL := test.MustParseURL("https://example.com/oauth2/123")

		webExpected := baseExpected
		webExpected.Issuer = issuerURL.String()
		webExpected.AuthorizationEndpoint = issuerURL.String() + "/authorize"
		webExpected.PresentationDefinitionEndpoint = issuerURL.String() + "/presentation_definition"
		webExpected.TokenEndpoint = issuerURL.String() + "/token"

		md := authorizationServerMetadata(issuerURL)
		assert.Equal(t, webExpected, md)
	})
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
		ClientIdScheme:          "did",
	}
	assert.Equal(t, expected, clientMetadata())
}
