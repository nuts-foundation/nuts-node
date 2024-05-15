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

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
)

func Test_authorizationServerMetadata(t *testing.T) {
	presentationDefinitionURISupported := true
	didExample := did.MustParseDID("did:example:test")
	baseExpected := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      "openid4vp:",
		ClientIdSchemesSupported:                   []string{"did"},
		DPoPSigningAlgValuesSupported:              jwx.SupportedAlgorithmsAsStrings(),
		GrantTypesSupported:                        []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		Issuer:                                     didExample.String(),
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
		md, err := authorizationServerMetadata(didExample)
		assert.NoError(t, err)
		assert.Equal(t, baseExpected, *md)
	})
	t.Run("did:web", func(t *testing.T) {
		didWeb := did.MustParseDID("did:web:example.com:iam:123")
		identity := test.MustParseURL("https://example.com/iam/123")
		oauth2Base := test.MustParseURL("https://example.com/oauth2/did:web:example.com:iam:123")

		webExpected := baseExpected
		webExpected.Issuer = identity.String()
		webExpected.AuthorizationEndpoint = oauth2Base.String() + "/authorize"
		webExpected.PresentationDefinitionEndpoint = oauth2Base.String() + "/presentation_definition"
		webExpected.TokenEndpoint = oauth2Base.String() + "/token"

		md, err := authorizationServerMetadata(didWeb)
		assert.NoError(t, err)
		assert.Equal(t, webExpected, *md)
	})
}

func Test_clientMetadata(t *testing.T) {
	core.GitVersion = "testVersion"
	expected := OAuthClientMetadata{
		RedirectURIs:            nil,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
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
	assert.Equal(t, expected, clientMetadata(url.URL{}))
}
