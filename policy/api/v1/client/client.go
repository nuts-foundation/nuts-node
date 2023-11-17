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

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
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

// PresentationDefinition retrieves the presentation definition from the presentation definition endpoint for the given scope and .
func (hb HTTPClient) PresentationDefinition(ctx context.Context, policyEndpoint string, authorizer did.DID, scopes string) (*pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := core.ParsePublicURL(policyEndpoint, hb.strictMode)
	if err != nil {
		return nil, err
	}
	presentationDefinitionURL.Path = fmt.Sprintf("%s/presentation_definition", presentationDefinitionURL.Path)
	presentationDefinitionURL.RawQuery = url.Values{"scope": []string{scopes}, "authorizer": []string{authorizer.String()}}.Encode()

	// create a GET request with query params
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, presentationDefinitionURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hb.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if httpErr := core.TestResponseCode(http.StatusOK, response); httpErr != nil {
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
