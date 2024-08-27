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
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
)

func authorizationServerMetadata(ownedDID did.DID, issuerURL *url.URL, supportedDIDMethods []string) oauth.AuthorizationServerMetadata {
	var didMethods []string
	for _, method := range supportedDIDMethods {
		didMethods = append(didMethods, fmt.Sprintf("did:%s", method))
	}
	metadata := &oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      "openid4vp:",
		ClientIdSchemesSupported:                   clientIdSchemesSupported,
		SupportedClientIDDIDMethods:                didMethods,
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
	if ownedDID.Method == "web" {
		// add endpoints for did:web
		metadata.AuthorizationEndpoint = issuerURL.JoinPath("authorize").String()
		metadata.PresentationDefinitionEndpoint = issuerURL.JoinPath("presentation_definition").String()
		metadata.TokenEndpoint = issuerURL.JoinPath("token").String()
	}
	return *metadata
}

// staticAuthorizationServerMetadata is used in the OpenID4VP flow when authorization server (wallet) issuer is unknown.
// Note: several specs (OpenID4VP, SIOPv2, OpenID core) define a static authorization server configuration that currently are conflicting.
func staticAuthorizationServerMetadata() oauth.AuthorizationServerMetadata {
	return oauth.AuthorizationServerMetadata{
		Issuer:                 "https://self-issued.me/v2",
		AuthorizationEndpoint:  "openid4vp:",
		ResponseTypesSupported: []string{oauth.VPTokenResponseType},
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
		ClientIdScheme:          didClientIDScheme,
	}
}

// filterDIDOnMethod filters the candidates based on the supported DID methods.
// The supported DID methods include that `did:` prefix.
func filterDIDOnMethod(candidates []did.DID, supportedDIDMethods []string) []did.DID {
	var filtered []did.DID
	for _, candidate := range candidates {
		for _, method := range supportedDIDMethods {
			if "did:"+candidate.Method == method {
				filtered = append(filtered, candidate)
				break
			}
		}
	}
	return filtered
}
