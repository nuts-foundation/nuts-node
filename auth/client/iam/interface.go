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
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// Client defines OpenID4VP client methods using the IAM OpenAPI Spec.
type Client interface {
	// AccessToken requests an access token at the oauth2 token endpoint.
	// The token endpoint can be a regular OAuth2 token endpoint or OpenID4VCI-related endpoint.
	// The response will be unmarshalled into the given tokenResponseOut parameter.
	AccessToken(ctx context.Context, code string, verifier did.DID, callbackURI string, clientID did.DID, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error)
	// AuthorizationServerMetadata returns the metadata of the remote wallet.
	AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error)
	// ClientMetadata returns the metadata of the remote verifier.
	ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error)
	// PostError posts an error to the verifier. If it fails, an error is returned.
	PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error)
	// PostAuthorizationResponse posts the authorization response to the verifier. If it fails, an error is returned.
	PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error)
	// PresentationDefinition returns the presentation definition from the given endpoint.
	PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error)
	// RequestRFC021AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC021.
	RequestRFC021AccessToken(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string, useDPoP bool) (*oauth.TokenResponse, error)

	OpenIdConfiguration(ctx context.Context, serverURL string) (*oauth.OpenIDConfigurationMetadata, error)

	OpenIdCredentialIssuerMetadata(ctx context.Context, webDID did.DID) (*oauth.OpenIDCredentialIssuerMetadata, error)

	VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJWT string) (*CredentialResponse, error)
	// RequestObject is returned from the authorization request's 'request_uri' defined in RFC9101.
	RequestObject(ctx context.Context, requestURI string) (string, error)
}
