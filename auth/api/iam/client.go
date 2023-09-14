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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	httpClient core.HTTPRequestDoer
}

// NewHTTPClient creates a new api client.
func NewHTTPClient(config core.ClientConfig) HTTPClient {
	return HTTPClient{
		httpClient: core.MustCreateHTTPClient(config, nil),
	}
}

func (hb HTTPClient) clientWithBase(baseURL string) ClientInterface {
	// can only be used for public APIs
	response, err := NewClientWithResponses(baseURL, WithHTTPClient(hb.httpClient))
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HTTPClient) OAuthAuthorizationServerMetadata(ctx context.Context, serverDID did.DID) (*OAuthAuthorizationServerMetadata, error) {
	if serverDID.Method != "web" {
		return nil, fmt.Errorf("unsupported DID method: %s", serverDID.Method)
	}
	// TODO: ignoring root web did for now. We can't use the generated client for that type of web:did :(
	serverURL := strings.ReplaceAll(serverDID.ID, ":", "/")
	// remove % encodings
	serverURL, err := url.QueryUnescape(serverURL)
	if err != nil {
		return nil, err
	}

	response, err := hb.clientWithBase(fmt.Sprintf("https://%s", serverURL)).OAuthAuthorizationServerMetadata(ctx, serverDID.String())
	if err != nil {
		return nil, err
	}

	if err = core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}

	var metadata OAuthAuthorizationServerMetadata
	var data []byte

	if data, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}

	return &metadata, nil
}
