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
	httpClient *core.StrictHTTPClient
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

// PresentationDefinition retrieves the presentation definition for the given web DID and scope(s).
// We pass the endpoint url for the presentation definition endpoint because we already retrieved the metadata in a previous step.
// The scopes are evaluated as raw query params and encoded if needed.
func (hb HTTPClient) PresentationDefinition(ctx context.Context, definitionEndpoint string, scopes []string) ([]pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := url.Parse(definitionEndpoint)
	if err != nil {
		return nil, err
	}
	presentationDefinitionURL.RawQuery = url.Values{"scope": scopes}.Encode()

	// create a GET request with scope query param
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, presentationDefinitionURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	definitions := make([]pe.PresentationDefinition, 0)
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &definitions); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return definitions, nil
}

func (hb HTTPClient) AccessToken(ctx context.Context, tokenEndpoint string, vp vc.VerifiablePresentation, submission pe.PresentationSubmission, scopes []string) (oauth.TokenResponse, error) {
	var token oauth.TokenResponse
	presentationDefinitionURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return token, err
	}

	// create a POST request with x-www-form-urlencoded body
	assertion, _ := json.Marshal(vp)
	presentationSubmission, _ := json.Marshal(submission)
	data := url.Values{}
	data.Set("grant_type", "vp_token-bearer")
	data.Set("assertion", string(assertion))
	data.Set("presentation_submission", string(presentationSubmission))
	data.Set("scope", strings.Join(scopes, " "))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, presentationDefinitionURL.String(), strings.NewReader(data.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return token, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return token, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return token, err
	}

	var responseData []byte
	if responseData, err = io.ReadAll(response.Body); err != nil {
		return token, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(responseData, &token); err != nil {
		return token, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(responseData))
	}
	return token, nil
}
