/*
 * Copyright (C) 2026 Nuts community
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

package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nuts-foundation/nuts-node/core"
)

const evaluationsPath = "/access/v1/evaluations"

// Client is an HTTP client for the AuthZen Access Evaluations API.
type Client struct {
	endpoint   string
	httpClient core.HTTPRequestDoer
}

// NewClient creates a new AuthZen client. The endpoint is the base URL of the PDP.
// The httpClient handles timeouts and TLS configuration.
func NewClient(endpoint string, httpClient core.HTTPRequestDoer) *Client {
	return &Client{
		endpoint:   endpoint,
		httpClient: httpClient,
	}
}

// Evaluate sends a batch evaluation request and returns a map of scope → decision.
func (c *Client) Evaluate(ctx context.Context, req EvaluationsRequest) (map[string]bool, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("authzen: marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+evaluationsPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("authzen: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("authzen: execute request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("authzen: PDP returned HTTP %d: %s", httpResp.StatusCode, string(respBody))
	}

	var resp EvaluationsResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("authzen: decode response: %w", err)
	}
	if len(resp.Evaluations) != len(req.Evaluations) {
		return nil, fmt.Errorf("authzen: expected %d evaluations, got %d", len(req.Evaluations), len(resp.Evaluations))
	}

	decisions := make(map[string]bool, len(req.Evaluations))
	for i, eval := range resp.Evaluations {
		decisions[req.Evaluations[i].Resource.ID] = eval.Decision
	}
	return decisions, nil
}
