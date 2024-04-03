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
	"net/url"
)

// Client defines OpenID4VP client methods using the IAM OpenAPI Spec.
type Client interface {
	// AccessToken requests an access token at the oauth2 token endpoint.
	AccessToken(ctx context.Context, code string, verifier did.DID, callbackURI string, clientID did.DID, codeVerifier string) (*oauth.TokenResponse, error)
	// AuthorizationServerMetadata returns the metadata of the remote wallet.
	AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error)
	// ClientMetadata returns the metadata of the remote verifier.
	ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error)
	// CreateAuthorizationRequest creates an OAuth2.0 authorizationRequest redirect URL that redirects to the authorization server.
	// It can create both regular OAuth2 requests and OpenID4VP requests due to the RequestModifier.
	// It's able to create an unsigned request and a signed request (JAR) based on the OAuth Server Metadata.
	// By default, it adds the following parameters to a regular request:
	// - client_id
	// and to a signed request:
	// - client_id
	// - jwt.Issuer
	// - jwt.Audience
	// - nonce
	// any of these params can be overridden by the RequestModifier.
	CreateAuthorizationRequest(ctx context.Context, client did.DID, server did.DID, modifier RequestModifier) (*url.URL, error)
	// PostError posts an error to the verifier. If it fails, an error is returned.
	PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error)
	// PostAuthorizationResponse posts the authorization response to the verifier. If it fails, an error is returned.
	PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error)
	// PresentationDefinition returns the presentation definition from the given endpoint.
	PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error)
	// RequestRFC021AccessToken is called by the local EHR node to request an access token from a remote Nuts node using Nuts RFC021.
	RequestRFC021AccessToken(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string) (*oauth.TokenResponse, error)
}

// RequestModifier is a function that modifies the claims/params of a unsigned or signed request (JWT)
type RequestModifier func(claims map[string]interface{})
