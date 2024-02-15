/*
 * Nuts node
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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

var _ Client = (*OpenID4VPClient)(nil)

type OpenID4VPClient struct {
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	jwtSigner         nutsCrypto.JWTSigner
	keyResolver       resolver.KeyResolver
	strictMode        bool
	wallet            holder.Wallet
}

// NewClient returns an implementation of Holder
func NewClient(wallet holder.Wallet, keyResolver resolver.KeyResolver, jwtSigner nutsCrypto.JWTSigner, strictMode bool, httpClientTimeout time.Duration, httpClientTLS *tls.Config) *OpenID4VPClient {
	return &OpenID4VPClient{
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
		keyResolver:       keyResolver,
		jwtSigner:         jwtSigner,
		strictMode:        strictMode,
		wallet:            wallet,
	}
}

func (c *OpenID4VPClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := c.newHTTPClient()

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth client metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error) {
	iamClient := c.newHTTPClient()

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	validURL := *responseURL
	if verifierClientState != "" {
		validURL = http.AddQueryParams(*responseURL, map[string]string{
			oauth.StateParam: verifierClientState,
		})
	}
	redirectURL, err := iamClient.PostError(ctx, auth2Error, validURL)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}

	return redirectURL, nil
}

func (c *OpenID4VPClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error) {
	iamClient := c.newHTTPClient()

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	redirectURL, err := iamClient.PostAuthorizationResponse(ctx, vp, presentationSubmission, *responseURL, state)
	if err == nil {
		return redirectURL, nil
	}

	return "", fmt.Errorf("failed to post authorization response to verifier: %w", err)
}

func (c *OpenID4VPClient) PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error) {
	iamClient := c.newHTTPClient()
	parsedURL, err := core.ParsePublicURL(endpoint, c.strictMode)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, *parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	return presentationDefinition, nil
}

func (c *OpenID4VPClient) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := c.newHTTPClient()
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) AccessToken(ctx context.Context, code string, verifier did.DID, callbackURI string, clientID did.DID) (*oauth.TokenResponse, error) {
	iamClient := c.newHTTPClient()
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.TokenEndpoint) == 0 {
		return nil, fmt.Errorf("no token endpoint found in Authorization Server metadata: %s", verifier)
	}
	// call token endpoint
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID.String())
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set(oauth.RedirectURIParam, callbackURI)
	token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("remote server: error creating access token: %w", err)
	}
	return &token, nil
}

func (c *OpenID4VPClient) CreateAuthorizationRequest(ctx context.Context, client did.DID, server did.DID, modifier RequestModifier) (*url.URL, error) {
	// we want to make a call according to §4.1.1 of RFC6749, https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
	// The URL should be listed in the verifier metadata under the "authorization_endpoint" key
	iamClient := c.newHTTPClient()
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.AuthorizationEndpoint) == 0 {
		return nil, fmt.Errorf("no authorization endpoint found in metadata for %s", server)
	}
	endpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
	}
	// one default param for both signed and unsigned
	params := map[string]interface{}{
		oauth.ClientIDParam: client.String(),
	}
	// use JAR (JWT Authorization Request, RFC9101) if the verifier supports/requires it
	if metadata.RequireSignedRequestObject {
		// construct JWT
		// first get a valid keyID from the vdr.KeyResolver
		keyId, _, err := c.keyResolver.ResolveKey(client, nil, resolver.AssertionMethod)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve key for signing authorization request: %w", err)
		}
		// default claims for JAR
		params[jwt.IssuerKey] = client.String()
		params[jwt.AudienceKey] = server.String()
		params[oauth.ClientIDParam] = client.String()
		// added by default, can be overriden by the caller
		params[oauth.NonceParam] = nutsCrypto.GenerateNonce()

		// additional claims can be added by the caller
		modifier(params)

		token, err := c.jwtSigner.SignJWT(ctx, params, nil, keyId.String())
		if err != nil {
			return nil, fmt.Errorf("failed to sign authorization request: %w", err)
		}
		redirectURL := http.AddQueryParams(*endpoint, map[string]string{
			oauth.ClientIDParam: client.String(),
			oauth.RequestParam:  token,
		})
		return &redirectURL, nil
	}
	// else return an unsigned regular authorization request
	// left here for completeness, node 2 node interaction always uses JAR since the AS metadata has it hardcoded

	// additional claims can be added by the caller
	modifier(params)
	stringParams := make(map[string]string)
	for k, v := range params {
		stringParams[k] = fmt.Sprintf("%v", v)
	}
	redirectURL := http.AddQueryParams(*endpoint, stringParams)
	return &redirectURL, nil
}

func (c *OpenID4VPClient) RequestRFC021AccessToken(ctx context.Context, requester did.DID, verifier did.DID, scopes string) (*oauth.TokenResponse, error) {
	iamClient := c.newHTTPClient()
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}

	// get the presentation definition from the verifier
	parsedURL, err := core.ParsePublicURL(metadata.PresentationDefinitionEndpoint, c.strictMode)
	if err != nil {
		return nil, err
	}
	presentationDefinitionURL := http.AddQueryParams(*parsedURL, map[string]string{
		"scope": scopes,
	})
	presentationDefinition, err := c.PresentationDefinition(ctx, presentationDefinitionURL.String())
	if err != nil {
		return nil, err
	}

	params := holder.BuildParams{
		Audience: verifier.String(),
		Expires:  time.Now().Add(time.Second * 5),
		Nonce:    nutsCrypto.GenerateNonce(),
	}
	vp, submission, err := c.wallet.BuildSubmission(ctx, requester, *presentationDefinition, metadata.VPFormats, params)
	if err != nil {
		return nil, err
	}

	assertion := vp.Raw()
	presentationSubmission, _ := json.Marshal(submission)
	data := url.Values{}
	data.Set(oauth.GrantTypeParam, oauth.VpTokenGrantType)
	data.Set(oauth.AssertionParam, assertion)
	data.Set(oauth.PresentationSubmissionParam, string(presentationSubmission))
	data.Set(oauth.ScopeParam, scopes)
	log.Logger().Tracef("Requesting access token from '%s' for scope '%s'\n  VP: %s\n  Submission: %s", metadata.TokenEndpoint, scopes, assertion, string(presentationSubmission))
	token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, data)
	if err != nil {
		// the error could be a http error, we just relay it here to make use of any 400 status codes.
		return nil, err
	}
	return &oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &scopes,
	}, nil
}
