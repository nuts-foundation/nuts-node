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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	strictMode bool
	httpClient core.HTTPRequestDoer
}

// NewHTTPClient creates a new api client.
func NewHTTPClient(strictMode bool, timeout time.Duration, tlsConfig *tls.Config) HTTPClient {
	return HTTPClient{
		strictMode: strictMode,
		httpClient: core.NewStrictHTTPClient(strictMode, timeout, tlsConfig),
	}
}

// OAuthAuthorizationServerMetadata retrieves the OAuth authorization server metadata for the given web DID.
func (hb HTTPClient) OAuthAuthorizationServerMetadata(ctx context.Context, webDID did.DID) (*oauth.AuthorizationServerMetadata, error) {
	serverURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, err
	}

	metadataURL, err := oauth.IssuerIdToWellKnown(serverURL.String(), oauth.AuthzServerWellKnown, hb.strictMode)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	var metadata oauth.AuthorizationServerMetadata
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return &metadata, nil
}

// PresentationDefinition retrieves the presentation definition from the presentation definition endpoint (as specified by RFC021) for the given scope.
func (hb HTTPClient) PresentationDefinition(ctx context.Context, definitionEndpoint string, scopes string) (*pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := core.ParsePublicURL(definitionEndpoint, hb.strictMode)

	if err != nil {
		return nil, err
	}
	presentationDefinitionURL.RawQuery = url.Values{"scope": []string{scopes}}.Encode()

	// create a GET request with scope query param
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, presentationDefinitionURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if httpErr := core.TestResponseCode(http.StatusOK, response); httpErr != nil {
		rse := httpErr.(core.HttpError)
		if ok, oauthErr := oauth.TestOAuthErrorCode(rse.ResponseBody, oauth.InvalidScope); ok {
			return nil, oauthErr
		}
		return nil, httpErr
	}

	var presentationDefinition pe.PresentationDefinition
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &presentationDefinition); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w", err)
	}

	return &presentationDefinition, nil
}

func (hb HTTPClient) AccessToken(ctx context.Context, tokenEndpoint string, vp vc.VerifiablePresentation, submission pe.PresentationSubmission, scopes string) (oauth.TokenResponse, error) {
	var token oauth.TokenResponse
	presentationDefinitionURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return token, err
	}

	// create a POST request with x-www-form-urlencoded body
	assertion, _ := json.Marshal(vp)
	presentationSubmission, _ := json.Marshal(submission)
	data := url.Values{}
	data.Set(oauth.GrantTypeParam, oauth.VpTokenGrantType)
	data.Set(oauth.AssertionParam, string(assertion))
	data.Set(oauth.PresentationSubmissionParam, string(presentationSubmission))
	data.Set(oauth.ScopeParam, scopes)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, presentationDefinitionURL.String(), strings.NewReader(data.Encode()))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return token, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return token, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		// check for oauth error
		if innerErr := core.TestResponseCode(http.StatusBadRequest, response); innerErr != nil {
			// a non oauth error, the response body could contain a lot of stuff. We'll log and return the entire error
			log.Logger().Debugf("authorization server token endpoint returned non oauth error (statusCode=%d)", response.StatusCode)
			return token, err
		}
		httpErr := err.(core.HttpError)
		oauthError := oauth.OAuth2Error{}
		if err := json.Unmarshal(httpErr.ResponseBody, &oauthError); err != nil {
			return token, fmt.Errorf("unable to unmarshal OAuth error response: %w", err)
		}

		return token, oauthError
	}

	var responseData []byte
	if responseData, err = io.ReadAll(response.Body); err != nil {
		return token, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(responseData, &token); err != nil {
		// Cut off the response body to 100 characters max to prevent logging of large responses
		responseBodyString := string(responseData)
		if len(responseBodyString) > 100 {
			responseBodyString = responseBodyString[:100] + "...(clipped)"
		}
		return token, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(responseData))
	}
	return token, nil
}
