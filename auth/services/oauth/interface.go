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

package oauth

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
	"net/url"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// RelyingParty implements the OAuth2 relying party role.
type RelyingParty interface {
	CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error)
	// CreateAuthorizationRequest creates an OAuth2.0 authorizationRequest redirect URL that redirects to the authorization server.
	CreateAuthorizationRequest(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string, clientState string) (*url.URL, error)

	// RequestRFC003AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC003.
	RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authServerEndpoint url.URL) (*oauth.TokenResponse, error)
	// RequestRFC021AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC021.
	RequestRFC021AccessToken(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string) (*oauth.TokenResponse, error)
}

// AuthorizationServer implements the OAuth2 authorization server role.
type AuthorizationServer interface {
	// Configure sets up the client. Enable secureMode to have it behave more safe (e.g., sanitize internal errors).
	Configure(clockSkewInMilliseconds int, secureMode bool) error
	// CreateAccessToken is called by remote Nuts nodes to create an access token,
	// which can be used to access the local organization's XIS resources.
	// It returns an oauth.ErrorResponse rather than a regular Go error, because the errors that may be returned are tightly specified.
	CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*oauth.TokenResponse, *oauth.OAuth2Error)
	IntrospectAccessToken(ctx context.Context, token string) (*services.NutsAccessToken, error)
}

// Verifier implements the OpenID4VP Verifier role.
type Verifier interface {
	// AuthorizationServerMetadata returns the metadata of the remote wallet.
	AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error)
	// ClientMetadataURL constructs the URL to the client metadata of the local verifier.
	ClientMetadataURL(webdid did.DID) (*url.URL, error)
}

// Holder implements the OpenID4VP Holder role which acts as Authorization server in the OpenID4VP flow.
type Holder interface {
	// BuildPresentation builds a Verifiable Presentation based on the given presentation definition.
	BuildPresentation(ctx context.Context, walletDID did.DID, presentationDefinition pe.PresentationDefinition, acceptedFormats map[string]map[string][]string, nonce string) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error)
	// ClientMetadata returns the metadata of the remote verifier.
	ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error)
	// PostError posts an error to the verifier. If it fails, an error is returned.
	PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string) (string, error)
	// PostAuthorizationResponse posts the authorization response to the verifier. If it fails, an error is returned.
	PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string) (string, error)
	// PresentationDefinition returns the presentation definition from the given endpoint.
	PresentationDefinition(ctx context.Context, presentationDefinitionParam string) (*pe.PresentationDefinition, error)
}
