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

package openid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
)

// IssuerAPIClient defines the API client used by the wallet to communicate with the credential issuer.
type IssuerAPIClient interface {
	OAuth2Client

	// Metadata returns the Credential Issuer Metadata.
	Metadata() CredentialIssuerMetadata
	// RequestCredential requests a credential from the issuer.
	RequestCredential(ctx context.Context, request CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
	// RequestNonce requests a fresh c_nonce from the issuer's Nonce Endpoint (v1.0 Section 7).
	RequestNonce(ctx context.Context) (*NonceResponse, error)
}

// NewIssuerAPIClient resolves the Credential Issuer Metadata from the well-known endpoint
// and returns a client that can be used to communicate with the issuer.
func NewIssuerAPIClient(ctx context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (IssuerAPIClient, error) {
	if credentialIssuerIdentifier == "" {
		return nil, errors.New("empty Credential Issuer Identifier")
	}

	// Load OpenID4VCI metadata and OIDC metadata
	// TODO: Use the OpenID4VCI credential issuers metadata to load the OIDC metadata?
	metadata, err := loadCredentialIssuerMetadata(ctx, credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load Credential Issuer Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}
	providerMetadata, err := loadOIDCProviderMetadata(ctx, credentialIssuerIdentifier, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to load OIDC Provider Metadata (identifier=%s): %w", credentialIssuerIdentifier, err)
	}

	return newIssuerClientFromMD(httpClient, *providerMetadata, *metadata)
}

// newIssuerClientFromMD creates a new IssuerAPIClient from preloaded metadata.
func newIssuerClientFromMD(httpClient core.HTTPRequestDoer, oidcProvider ProviderMetadata, credentialIssuer CredentialIssuerMetadata) (IssuerAPIClient, error) {
	return &defaultIssuerAPIClient{
		httpOAuth2Client: httpOAuth2Client{
			httpClient: httpClient,
			metadata:   oidcProvider,
		},
		identifier: credentialIssuer.CredentialIssuer,
		httpClient: httpClient,
		metadata:   credentialIssuer,
	}, nil
}

var _ IssuerAPIClient = (*defaultIssuerAPIClient)(nil)
var HttpClientTrace *httptrace.ClientTrace = nil

type defaultIssuerAPIClient struct {
	httpOAuth2Client

	identifier string
	httpClient core.HTTPRequestDoer
	metadata   CredentialIssuerMetadata
}

func (h defaultIssuerAPIClient) RequestCredential(ctx context.Context, request CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	requestBody, _ := json.Marshal(request)

	httpRequest, _ := http.NewRequestWithContext(ctx, "POST", h.metadata.CredentialEndpoint, bytes.NewReader(requestBody))
	httpRequest.Header.Add("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Add("Content-Type", "application/json")
	credentialResponse, err := doCredentialRequest(h.httpClient, httpRequest)
	if err != nil {
		return nil, err
	}
	if len(credentialResponse.Credentials) == 0 {
		return nil, errors.New("credential response does not contain any credentials")
	}
	// We only support single credential issuance for now
	var credential vc.VerifiableCredential
	credentialJSON, _ := json.Marshal(credentialResponse.Credentials[0].Credential)
	err = json.Unmarshal(credentialJSON, &credential)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal received credential: %w", err)
	}
	return &credential, nil
}

// doCredentialRequest performs the HTTP request to the credential endpoint.
// It returns structured OpenID4VCI errors when the server returns an error response,
// allowing callers to detect specific error codes like invalid_nonce.
func doCredentialRequest(httpClient core.HTTPRequestDoer, httpRequest *http.Request) (*CredentialResponse, error) {
	if HttpClientTrace != nil {
		httpRequest = httpRequest.WithContext(httptrace.WithClientTrace(httpRequest.Context(), HttpClientTrace))
	}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("credential request http error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("credential request read error: %w", err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		var oidcError Error
		if json.Unmarshal(responseBody, &oidcError) == nil && oidcError.Code != "" {
			oidcError.StatusCode = httpResponse.StatusCode
			return nil, oidcError
		}
		return nil, fmt.Errorf("credential request failed (status %d)", httpResponse.StatusCode)
	}
	var credentialResponse CredentialResponse
	if err := json.Unmarshal(responseBody, &credentialResponse); err != nil {
		return nil, fmt.Errorf("credential response unmarshal error: %w", err)
	}
	return &credentialResponse, nil
}

func (h defaultIssuerAPIClient) RequestNonce(ctx context.Context) (*NonceResponse, error) {
	if h.metadata.NonceEndpoint == "" {
		return nil, errors.New("issuer does not advertise a nonce endpoint")
	}
	var nonceResponse NonceResponse
	httpRequest, _ := http.NewRequestWithContext(ctx, "POST", h.metadata.NonceEndpoint, http.NoBody)
	err := httpDo(h.httpClient, httpRequest, &nonceResponse)
	if err != nil {
		return nil, fmt.Errorf("nonce request failed: %w", err)
	}
	if nonceResponse.CNonce == "" {
		return nil, errors.New("nonce endpoint returned empty c_nonce")
	}
	return &nonceResponse, nil
}

func (h defaultIssuerAPIClient) Metadata() CredentialIssuerMetadata {
	return h.metadata
}

func loadCredentialIssuerMetadata(ctx context.Context, identifier string, httpClient core.HTTPRequestDoer) (*CredentialIssuerMetadata, error) {
	// TODO: what about caching?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2034
	result := CredentialIssuerMetadata{}
	err := httpGet(ctx, httpClient, core.JoinURLPaths(identifier, CredentialIssuerMetadataWellKnownPath), &result)
	if err != nil {
		return nil, err
	}
	if result.CredentialIssuer != identifier {
		return nil, errors.New("invalid credential issuer meta data: identifier in meta data differs from requested identifier")
	}
	if len(result.CredentialEndpoint) == 0 {
		return nil, errors.New("invalid credential issuer meta data: does not contain credential endpoint")
	}
	return &result, nil
}

func loadOIDCProviderMetadata(ctx context.Context, identifier string, httpClient core.HTTPRequestDoer) (*ProviderMetadata, error) {
	// TODO: what about caching?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2034
	result := ProviderMetadata{}
	err := httpGet(ctx, httpClient, core.JoinURLPaths(identifier, ProviderMetadataWellKnownPath), &result)
	if err != nil {
		return nil, err
	}
	if result.Issuer != identifier {
		return nil, errors.New("invalid OpenID provider meta data: issuer in meta data differs from requested issuer")
	}
	if len(result.TokenEndpoint) == 0 {
		return nil, errors.New("invalid OpenID provider meta data: does not contain token endpoint")
	}
	return &result, nil
}

func httpGet(ctx context.Context, httpClient core.HTTPRequestDoer, targetURL string, result interface{}) error {

	httpRequest, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	return httpDo(httpClient, httpRequest, result)
}

func httpDo(httpClient core.HTTPRequestDoer, httpRequest *http.Request, result interface{}) error {
	if HttpClientTrace != nil {
		httpRequest = httpRequest.WithContext(httptrace.WithClientTrace(httpRequest.Context(), HttpClientTrace))
	}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("http request error: %w", err)
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("read error (%s): %w", httpRequest.URL, err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		responseBodyStr := string(responseBody)
		// If longer than 100 characters, truncate
		if len(responseBodyStr) > 100 {
			responseBodyStr = responseBodyStr[:100] + "..."
		}
		log.Logger().Debugf("HTTP response body: %s", responseBodyStr)
		return fmt.Errorf("unexpected http response code (%s): %d", httpRequest.URL, httpResponse.StatusCode)
	}
	if result != nil {
		if err := json.Unmarshal(responseBody, result); err != nil {
			return fmt.Errorf("%T JSON unmarshal error: %w", result, err)
		}
	}
	return nil
}

// OAuth2Client defines a generic OAuth2 client.
type OAuth2Client interface {
	// RequestAccessToken requests an access token from the Authorization Server.
	RequestAccessToken(grantType string, params map[string]string) (*oauth.TokenResponse, error)
}

var _ OAuth2Client = &httpOAuth2Client{}

type httpOAuth2Client struct {
	metadata   ProviderMetadata
	httpClient core.HTTPRequestDoer
}

func (c httpOAuth2Client) RequestAccessToken(grantType string, params map[string]string) (*oauth.TokenResponse, error) {
	values := url.Values{}
	values.Add("grant_type", grantType)
	for key, value := range params {
		values.Add(key, value)
	}
	httpRequest, _ := http.NewRequestWithContext(context.Background(), "POST", c.metadata.TokenEndpoint, strings.NewReader(values.Encode()))
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	var accessTokenResponse oauth.TokenResponse
	err := httpDo(c.httpClient, httpRequest, &accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("request access token error: %w", err)
	}
	return &accessTokenResponse, nil
}
