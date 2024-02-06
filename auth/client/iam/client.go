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
	"github.com/nuts-foundation/nuts-node/auth/log"
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
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

var _ Client = (*IAMClient)(nil)

type IAMClient struct {
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	strictMode        bool
	wallet            holder.Wallet
}

// NewClient returns an implementation of Holder
func NewClient(wallet holder.Wallet, strictMode bool, httpClientTimeout time.Duration, httpClientTLS *tls.Config) *IAMClient {
	return &IAMClient{
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
		strictMode:        strictMode,
		wallet:            wallet,
	}
}

func (v *IAMClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (v *IAMClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error) {
	iamClient := NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	responseURL, err := core.ParsePublicURL(verifierResponseURI, v.strictMode)
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

func (v *IAMClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error) {
	iamClient := NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	responseURL, err := core.ParsePublicURL(verifierResponseURI, v.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	redirectURL, err := iamClient.PostAuthorizationResponse(ctx, vp, presentationSubmission, *responseURL, state)
	if err == nil {
		return redirectURL, nil
	}

	return "", fmt.Errorf("failed to post authorization response to verifier: %w", err)
}

func (s *IAMClient) PresentationDefinition(ctx context.Context, presentationDefinitionParam string) (*pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := core.ParsePublicURL(presentationDefinitionParam, s.strictMode)
	if err != nil {
		return nil, err
	}

	iamClient := NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, *presentationDefinitionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	return presentationDefinition, nil
}

func (s *IAMClient) presentationDefinition(ctx context.Context, presentationDefinitionParam string, scopes string) (*pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := core.ParsePublicURL(presentationDefinitionParam, s.strictMode)
	if err != nil {
		return nil, err
	}

	presentationDefinitionURL.RawQuery = url.Values{"scope": []string{scopes}}.Encode()
	return s.PresentationDefinition(ctx, presentationDefinitionURL.String())
}

func (v *IAMClient) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (s *IAMClient) AccessToken(ctx context.Context, code string, verifier did.DID, callbackURI string, clientID did.DID) (*oauth.TokenResponse, error) {
	iamClient := NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
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

func (s *IAMClient) CreateAuthorizationRequest(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string, clientState string) (*url.URL, error) {
	// we want to make a call according to §4.1.1 of RFC6749, https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
	// The URL should be listed in the verifier metadata under the "authorization_endpoint" key
	iamClient := NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.AuthorizationEndpoint) == 0 {
		return nil, fmt.Errorf("no authorization endpoint found in metadata for %s", verifier)
	}
	endpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
	}
	// construct callback URL for wallet
	callbackURL, err := didweb.DIDToURL(requestHolder)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback URL: %w", err)
	}
	callbackURL = callbackURL.JoinPath(oauth.CallbackPath)
	redirectURL := http.AddQueryParams(*endpoint, map[string]string{
		"client_id":     requestHolder.String(),
		"response_type": "code",
		"scope":         scopes,
		"state":         clientState,
		"redirect_uri":  callbackURL.String(),
	})
	return &redirectURL, nil
}

func (s *IAMClient) RequestRFC021AccessToken(ctx context.Context, requester did.DID, verifier did.DID, scopes string) (*oauth.TokenResponse, error) {
	iamClient := NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}

	// get the presentation definition from the verifier
	presentationDefinition, err := s.presentationDefinition(ctx, metadata.PresentationDefinitionEndpoint, scopes)
	if err != nil {
		return nil, err
	}

	nonce := nutsCrypto.GenerateNonce()
	vp, submission, err := s.wallet.BuildSubmission(ctx, requester, *presentationDefinition, metadata.VPFormats, nonce, verifier.URI())
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
