/*
 * Copyright (C) 2024 Nuts community
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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery/api/v1/model"
	"io"
	"net/http"
	"net/url"
	"time"
)

// New creates a new DefaultHTTPClient.
func New(strictMode bool, timeout time.Duration, tlsConfig *tls.Config) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: core.NewStrictHTTPClient(strictMode, timeout, tlsConfig),
	}
}

var _ HTTPClient = &DefaultHTTPClient{}

// DefaultHTTPClient implements HTTPClient using HTTP.
type DefaultHTTPClient struct {
	client core.HTTPRequestDoer
}

func (h DefaultHTTPClient) Register(ctx context.Context, serviceEndpointURL string, presentation vc.VerifiablePresentation) error {
	requestBody, _ := json.Marshal(presentation)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceEndpointURL, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := h.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("failed to invoke remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	defer httpResponse.Body.Close()
	if err := core.TestResponseCode(201, httpResponse); err != nil {
		return fmt.Errorf("non-OK response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	return nil
}

func (h DefaultHTTPClient) Get(ctx context.Context, serviceEndpointURL string, tag string) ([]vc.VerifiablePresentation, string, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceEndpointURL, nil)
	if tag != "" {
		httpRequest.URL.RawQuery = url.Values{"tag": []string{tag}}.Encode()
	}
	if err != nil {
		return nil, "", err
	}
	httpResponse, err := h.client.Do(httpRequest)
	if err != nil {
		return nil, "", fmt.Errorf("failed to invoke remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	defer httpResponse.Body.Close()
	if err := core.TestResponseCode(200, httpResponse); err != nil {
		return nil, "", fmt.Errorf("non-OK response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	responseData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	var result model.PresentationsResponse
	if err := json.Unmarshal(responseData, &result); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	return result.Entries, result.Tag, nil
}
