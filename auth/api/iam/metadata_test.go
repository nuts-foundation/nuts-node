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
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func Test_authorizationServerMetadata(t *testing.T) {
	identity := "https://example.com/iam/did:nuts:123"
	identityURL, _ := url.Parse(identity)
	vpFormats := map[string]map[string][]string{
		"jwt_vc_json": {"alg_values_supported": []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}},
		"jwt_vp_json": {"alg_values_supported": []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}},
		"ldp_vc":      {"proof_type_values_supported": []string{"JsonWebSignature2020"}},
		"ldp_vp":      {"proof_type_values_supported": []string{"JsonWebSignature2020"}},
	}
	expected := OAuthAuthorizationServerMetadata{
		Issuer:                 identity,
		AuthorizationEndpoint:  identity + "/authorize",
		ResponseTypesSupported: []string{"code", "vp_token", "vp_token id_token"},
		ResponseModesSupported: []string{"query", "direct_post"},
		TokenEndpoint:          identity + "/token",
		GrantTypesSupported:    []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		PreAuthorizedGrantAnonymousAccessSupported: true,
		VPFormats:                vpFormats,
		VPFormatsSupported:       vpFormats,
		ClientIdSchemesSupported: []string{"did"},
	}
	assert.Equal(t, expected, authorizationServerMetadata(*identityURL))
}
