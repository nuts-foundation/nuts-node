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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"io"
	"net/http"
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
	// NewClientWithResponses can only return an error if an option returns an error.
	// When adding options, make sure to check if it can return an error, if so refactor to handle the error properly.
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HTTPClient) OAuthAuthorizationServerMetadata(ctx context.Context, webDID did.DID) (*OAuthAuthorizationServerMetadata, error) {
	// TODO: ignoring root web did for now. We can't use the generated client for that type of web:did :(
	serverURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, err
	}

	response, err := hb.clientWithBase(serverURL.String()).OAuthAuthorizationServerMetadata(ctx, webDID.String())
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
