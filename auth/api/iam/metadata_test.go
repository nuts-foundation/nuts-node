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
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestIssuerIdToWellKnown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/id"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/id", u.String())
	})
	t.Run("no path in issuer", func(t *testing.T) {
		issuer := "https://nuts.nl"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server", u.String())
	})
	t.Run("don't unescape path", func(t *testing.T) {
		issuer := "https://nuts.nl/iam/%2E%2E/still-has-iam"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, true)
		require.NoError(t, err)
		assert.Equal(t, "https://nuts.nl/.well-known/oauth-authorization-server/iam/%2E%2E/still-has-iam", u.String())
	})
	t.Run("https in strictmode", func(t *testing.T) {
		issuer := "http://nuts.nl/iam/id"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "scheme must be https")
		assert.Nil(t, u)
	})
	t.Run("no IP allowed", func(t *testing.T) {
		issuer := "http://127.0.0.1/iam/id"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, false)
		assert.ErrorContains(t, err, "hostname is IP")
		assert.Nil(t, u)
	})
	t.Run("invalid URL", func(t *testing.T) {
		issuer := "http:// /iam/id"
		u, err := oauth.IssuerIdToWellKnown(issuer, oauth.AuthzServerWellKnown, true)
		assert.ErrorContains(t, err, "invalid character \" \" in host name")
		assert.Nil(t, u)
	})
}

var vpFormats = map[string]map[string][]string{
	"jwt_vc_json": {"alg_values_supported": []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}},
	"jwt_vp_json": {"alg_values_supported": []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}},
	"ldp_vc":      {"proof_type_values_supported": []string{"JsonWebSignature2020"}},
	"ldp_vp":      {"proof_type_values_supported": []string{"JsonWebSignature2020"}},
}

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
		VPFormats:                                  vpFormatsSupported,
		VPFormatsSupported:                         vpFormatsSupported,
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
		VPFormats:               vpFormatsSupported,
		ClientIdScheme:          "did",
	}
	assert.Equal(t, expected, clientMetadata(url.URL{}))
}
