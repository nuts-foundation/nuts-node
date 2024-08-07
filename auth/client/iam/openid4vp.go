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
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/piprate/json-gold/ld"
	"net/http"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var _ Client = (*OpenID4VPClient)(nil)

type OpenID4VPClient struct {
	httpClient       HTTPClient
	jwtSigner        nutsCrypto.JWTSigner
	keyResolver      resolver.KeyResolver
	strictMode       bool
	wallet           holder.Wallet
	ldDocumentLoader ld.DocumentLoader
}

// NewClient returns an implementation of Holder
func NewClient(wallet holder.Wallet, keyResolver resolver.KeyResolver, jwtSigner nutsCrypto.JWTSigner, ldDocumentLoader ld.DocumentLoader, strictMode bool, httpClientTimeout time.Duration) *OpenID4VPClient {
	return &OpenID4VPClient{
		httpClient: HTTPClient{
			strictMode: strictMode,
			httpClient: client.NewWithCache(httpClientTimeout),
		},
		keyResolver:      keyResolver,
		jwtSigner:        jwtSigner,
		ldDocumentLoader: ldDocumentLoader,
		strictMode:       strictMode,
		wallet:           wallet,
	}
}

func (c *OpenID4VPClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := c.httpClient

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth client metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error) {
	iamClient := c.httpClient

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	validURL := *responseURL
	if verifierClientState != "" {
		validURL = nutsHttp.AddQueryParams(*responseURL, map[string]string{
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
	iamClient := c.httpClient

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
	iamClient := c.httpClient
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

func (c *OpenID4VPClient) AuthorizationServerMetadata(ctx context.Context, oauthIssuer string) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := c.httpClient
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, oauthIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) RequestObjectByGet(ctx context.Context, requestURI string) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	requestObject, err := iamClient.RequestObjectByGet(ctx, parsedURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}
func (c *OpenID4VPClient) RequestObjectByPost(ctx context.Context, requestURI string, walletMetadata oauth.AuthorizationServerMetadata) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	// TODO: consider adding a 'wallet_nonce'
	metadataBytes, _ := json.Marshal(walletMetadata)
	form := url.Values{oauth.WalletMetadataParam: {string(metadataBytes)}}
	requestObject, err := iamClient.RequestObjectByPost(ctx, parsedURL.String(), form)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}

func (c *OpenID4VPClient) AccessToken(ctx context.Context, code string, tokenEndpoint string, callbackURI string, clientID did.DID, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error) {
	iamClient := c.httpClient
	// validate tokenEndpoint
	parsedURL, err := core.ParsePublicURL(tokenEndpoint, c.strictMode)
	if err != nil {
		return nil, err
	}

	// call token endpoint
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID.String())
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set(oauth.RedirectURIParam, callbackURI)
	data.Set(oauth.CodeVerifierParam, codeVerifier)

	var dpopHeader string
	if useDPoP {
		// create DPoP header
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
		dpopHeader, err = c.dpop(ctx, clientID, *request)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP header: %w", err)
		}
	}

	token, err := iamClient.AccessToken(ctx, parsedURL.String(), data, dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("remote server: error creating access token: %w", err)
	}
	return &token, nil
}

func (c *OpenID4VPClient) RequestRFC021AccessToken(ctx context.Context, requester did.DID, authServerURL string, scopes string,
	useDPoP bool, credentials []vc.VerifiableCredential) (*oauth.TokenResponse, error) {
	iamClient := c.httpClient
	metadata, err := c.AuthorizationServerMetadata(ctx, authServerURL)
	if err != nil {
		return nil, err
	}

	// get the presentation definition from the verifier
	parsedURL, err := core.ParsePublicURL(metadata.PresentationDefinitionEndpoint, c.strictMode)
	if err != nil {
		return nil, err
	}
	presentationDefinitionURL := nutsHttp.AddQueryParams(*parsedURL, map[string]string{
		"scope": scopes,
	})
	presentationDefinition, err := c.PresentationDefinition(ctx, presentationDefinitionURL.String())
	if err != nil {
		return nil, err
	}

	params := holder.BuildParams{
		Audience: authServerURL,
		Expires:  time.Now().Add(time.Second * 5),
		Nonce:    nutsCrypto.GenerateNonce(),
	}

	targetWallet := c.wallet
	if len(credentials) > 0 {
		// This feature is used for presenting self-attested credentials which aren't signed (they're only protected by the VP's signature).
		// To make the API easier to use, we can set a few required fields if it's a self-attested credential.
		for i, credential := range credentials {
			credentials[i] = autoCorrectSelfAttestedCredential(credential, requester)
		}
		// We have additional credentials to present, aside from those in the persistent wallet.
		// Create a temporary in-memory wallet with the requester's persisted VCs and the
		targetWallet, err = c.walletWithExtraCredentials(ctx, requester, credentials)
		if err != nil {
			return nil, err
		}
	}

	vp, submission, err := targetWallet.BuildSubmission(ctx, requester, *presentationDefinition, metadata.VPFormatsSupported, params)
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

	// create DPoP header
	var dpopHeader string
	if useDPoP {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, nil)
		if err != nil {
			return nil, err
		}
		dpopHeader, err = c.dpop(ctx, requester, *request)
		if err != nil {
			return nil, fmt.Errorf("failed tocreate DPoP header: %w", err)
		}
	}

	log.Logger().Tracef("Requesting access token from '%s' for scope '%s'\n  VP: %s\n  Submission: %s", metadata.TokenEndpoint, scopes, assertion, string(presentationSubmission))
	token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, data, dpopHeader)
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

func (c *OpenID4VPClient) OpenIdCredentialIssuerMetadata(ctx context.Context, oauthIssuerURI string) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.OpenIdCredentialIssuerMetadata(ctx, oauthIssuerURI)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Openid credential issuer metadata: %w", err)
	}
	return rsp, nil
}

func (c *OpenID4VPClient) VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJWT string) (*CredentialResponse, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.VerifiableCredentials(ctx, credentialEndpoint, accessToken, proofJWT)
	if err != nil {
		return nil, fmt.Errorf("remote server: failed to retrieve credentials: %w", err)
	}
	return rsp, nil
}

func (c *OpenID4VPClient) walletWithExtraCredentials(ctx context.Context, subject did.DID, credentials []vc.VerifiableCredential) (holder.Wallet, error) {
	walletCredentials, err := c.wallet.List(ctx, subject)
	if err != nil {
		return nil, err
	}
	return holder.NewMemoryWallet(c.ldDocumentLoader, c.keyResolver, c.jwtSigner, map[did.DID][]vc.VerifiableCredential{
		subject: append(walletCredentials, credentials...),
	}), nil
}

func (c *OpenID4VPClient) dpop(ctx context.Context, requester did.DID, request http.Request) (string, error) {
	// find the key to sign the DPoP token with
	keyID, _, err := c.keyResolver.ResolveKey(requester, nil, resolver.AssertionMethod)
	if err != nil {
		return "", err
	}

	token := dpop.New(request)
	return c.jwtSigner.SignDPoP(ctx, *token, keyID)
}

// autoCorrectSelfAttestedCredential sets the required fields for a self-attested credential.
// These are provided through the API, and for convenience we set the required fields, if not already set.
// It only does this for unsigned credentials.
func autoCorrectSelfAttestedCredential(credential vc.VerifiableCredential, requester did.DID) vc.VerifiableCredential {
	if len(credential.Proof) > 0 {
		return credential
	}
	if credential.ID == nil {
		credential.ID, _ = ssi.ParseURI(uuid.NewString())
	}
	if credential.Issuer.String() == "" {
		credential.Issuer = requester.URI()
	}
	if credential.IssuanceDate.IsZero() {
		credential.IssuanceDate = time.Now()
	}
	var credentialSubject []map[string]interface{}
	_ = credential.UnmarshalCredentialSubject(&credentialSubject)
	if len(credentialSubject) == 1 {
		if _, ok := credentialSubject[0]["id"]; !ok {
			credentialSubject[0]["id"] = requester.String()
			credential.CredentialSubject[0] = credentialSubject[0]
		}
	}
	return credential
}
