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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/http/client"
	"io"
	"net/http"
	"net/url"
	"time"
)

// New creates a new DefaultHTTPClient.
func New(timeout time.Duration) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: client.New(timeout),
	}
}

var _ HTTPClient = &DefaultHTTPClient{}

// DefaultHTTPClient implements HTTPClient using HTTP.
type DefaultHTTPClient struct {
	client core.HTTPRequestDoer
}

func (h DefaultHTTPClient) Register(ctx context.Context, serviceEndpointURL string, presentation vc.VerifiablePresentation) error {
	requestBody, err := json.Marshal(presentation)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceEndpointURL, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Forwarded-Host", httpRequest.Host) // prevent cycles
	httpResponse, err := h.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("failed to invoke remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	defer httpResponse.Body.Close()
	if err := core.TestResponseCodeWithLog(201, httpResponse, log.Logger()); err != nil {
		// The response body is not part of the returned error: it comes from a remote server
		// and must not be reflected in our own API responses. TestResponseCodeWithLog logs it (truncated).
		return fmt.Errorf("non-OK response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	return nil
}

func (h DefaultHTTPClient) Get(ctx context.Context, serviceEndpointURL string, timestamp int) (map[string]vc.VerifiablePresentation, string, int, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceEndpointURL, nil)
	httpRequest.URL.RawQuery = url.Values{"timestamp": []string{fmt.Sprintf("%d", timestamp)}}.Encode()
	if err != nil {
		return nil, "", 0, err
	}
	httpRequest.Header.Set("X-Forwarded-Host", httpRequest.Host) // prevent cycles
	httpResponse, err := h.client.Do(httpRequest)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to invoke remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	defer httpResponse.Body.Close()
	if err := core.TestResponseCodeWithLog(200, httpResponse, log.Logger()); err != nil {
		// The response body is not part of the returned error: it comes from a remote server
		// and must not be reflected in our own API responses. TestResponseCodeWithLog logs it (truncated).
		return nil, "", 0, fmt.Errorf("non-OK response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	responseData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to read response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	var result PresentationsResponse
	if err := json.Unmarshal(responseData, &result); err != nil {
		return nil, "", 0, fmt.Errorf("failed to unmarshal response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	return result.Entries, result.Seed, result.Timestamp, nil
}
