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
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

func authorizationServerMetadata(ownedDID did.DID) (*oauth.AuthorizationServerMetadata, error) {
	if ownedDID.Method == "web" {
		return _authzMetadataDidWeb(ownedDID)
	}
	return _authzMetadataBase(ownedDID), nil
}

// _authzMetadataDidWeb should not be used directly, use authorizationServerMetadata instead.
func _authzMetadataDidWeb(ownedDID did.DID) (*oauth.AuthorizationServerMetadata, error) {
	identity, err := didweb.DIDToURL(ownedDID)
	if err != nil {
		return nil, err
	}
	oauth2BaseURL, err := createOAuth2BaseURL(ownedDID)
	if err != nil {
		// can't fail, already did DIDToURL above
		return nil, err
	}
	metadata := _authzMetadataBase(ownedDID)
	metadata.Issuer = identity.String()
	metadata.AuthorizationEndpoint = oauth2BaseURL.JoinPath("authorize").String()
	metadata.PresentationDefinitionEndpoint = oauth2BaseURL.JoinPath("presentation_definition").String()
	metadata.TokenEndpoint = oauth2BaseURL.JoinPath("token").String()
	return metadata, nil
}

// _authzMetadataBase should not be used directly, use authorizationServerMetadata instead.
func _authzMetadataBase(ownedDID did.DID) *oauth.AuthorizationServerMetadata {
	presentationDefinitionURISupported := true
	return &oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:                      "openid4vp:",
		ClientIdSchemesSupported:                   clientIdSchemesSupported,
		DPoPSigningAlgValuesSupported:              jwx.SupportedAlgorithmsAsStrings(),
		GrantTypesSupported:                        grantTypesSupported,
		Issuer:                                     ownedDID.String(), // todo: according to RFC8414 this should be a URL starting with https
		PreAuthorizedGrantAnonymousAccessSupported: true,
		PresentationDefinitionUriSupported:         &presentationDefinitionURISupported,
		RequireSignedRequestObject:                 true,
		ResponseModesSupported:                     responseModesSupported,
		ResponseTypesSupported:                     responseTypesSupported,
		VPFormats:                                  oauth.DefaultOpenIDSupportedFormats(),
		VPFormatsSupported:                         oauth.DefaultOpenIDSupportedFormats(),
		RequestObjectSigningAlgValuesSupported:     jwx.SupportedAlgorithmsAsStrings(),
	}
}

// staticAuthorizationServerMetadata is used in the OpenID4VP flow when authorization server (wallet) issuer is unknown.
// Note: several specs (OpenID4VP, SIOPv2, OpenID core) define a static authorization server configuration that currently are conflicting.
func staticAuthorizationServerMetadata() oauth.AuthorizationServerMetadata {
	return oauth.AuthorizationServerMetadata{
		Issuer:                 "https://self-issued.me/v2",
		AuthorizationEndpoint:  "openid4vp:",
		ResponseTypesSupported: []string{responseTypeVPToken},
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
		ClientIdScheme:          didScheme,
	}
}
