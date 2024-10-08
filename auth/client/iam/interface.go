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
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// Client defines OpenID4VP client methods using the IAM OpenAPI Spec.
type Client interface {
	// AccessToken requests an access token at the oauth2 token endpoint.
	// The token endpoint can be a regular OAuth2 token endpoint or OpenID4VCI-related endpoint.
	// The response will be unmarshalled into the given tokenResponseOut parameter.
	AccessToken(ctx context.Context, code string, tokenURI, callbackURI string, subject string, clientID string, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error)
	// AuthorizationServerMetadata returns the metadata of the remote wallet.
	// oauthIssuer is the URL of the issuer as specified by RFC 8414 (OAuth 2.0 Authorization Server Metadata).
	// For client_id's used by Nuts nodes, these are constructed as https://example.com/oauth2/<subject>
	AuthorizationServerMetadata(ctx context.Context, oauthIssuer string) (*oauth.AuthorizationServerMetadata, error)
	// ClientMetadata returns the metadata of the remote verifier.
	ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error)
	// PostError posts an error to the verifier. If it fails, an error is returned.
	PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error)
	// PostAuthorizationResponse posts the authorization response to the verifier. If it fails, an error is returned.
	PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error)
	// PresentationDefinition returns the presentation definition from the given endpoint.
	PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error)
	// RequestRFC021AccessToken is called by the local EHR node to request an access token from a remote OAuth2 Authorization Server using Nuts RFC021.
	RequestRFC021AccessToken(ctx context.Context, clientID string, subjectDID string, authServerURL string, scopes string, useDPoP bool,
		credentials []vc.VerifiableCredential) (*oauth.TokenResponse, error)

	// OpenIdCredentialIssuerMetadata returns the metadata of the remote credential issuer.
	// oauthIssuer is the URL of the issuer as specified by RFC 8414 (OAuth 2.0 Authorization Server Metadata).
	OpenIdCredentialIssuerMetadata(ctx context.Context, oauthIssuerURI string) (*oauth.OpenIDCredentialIssuerMetadata, error)
	// OpenIDConfiguration returns the OpenID Configuration of the remote wallet.
	OpenIDConfiguration(ctx context.Context, issuer string) (*oauth.OpenIDConfiguration, error)
	// VerifiableCredentials requests Verifiable Credentials from the issuer at the given endpoint.
	VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJWT string) (*CredentialResponse, error)
	// RequestObjectByGet retrieves the RequestObjectByGet from the authorization request's 'request_uri' endpoint using a GET method as defined in RFC9101/OpenID4VP.
	// This method is used when there is no 'request_uri_method', or its value is 'get'.
	RequestObjectByGet(ctx context.Context, requestURI string) (string, error)
	// RequestObjectByPost retrieves the RequestObjectByGet from the authorization request's 'request_uri' endpoint using a POST method as defined in RFC9101/OpenID4VP.
	// This method is used when the 'request_uri_method' is 'post'.
	RequestObjectByPost(ctx context.Context, requestURI string, walletMetadata oauth.AuthorizationServerMetadata) (string, error)
}
