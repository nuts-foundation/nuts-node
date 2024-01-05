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
	v1 "github.com/nuts-foundation/nuts-node/discovery/api/v1"
	"io"
	"net/http"
	"net/url"
)

// New creates a new HTTPInvoker.
func New(client core.HTTPRequestDoer) *HTTPInvoker {
	return &HTTPInvoker{
		client: client,
	}
}

var _ Invoker = &HTTPInvoker{}

// HTTPInvoker implements Invoker using HTTP.
type HTTPInvoker struct {
	client core.HTTPRequestDoer
}

func (h HTTPInvoker) Register(ctx context.Context, serviceEndpointURL string, presentation vc.VerifiablePresentation) error {
	requestBody, _ := presentation.MarshalJSON()
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

func (h HTTPInvoker) Get(ctx context.Context, serviceEndpointURL string, tag *string) ([]vc.VerifiablePresentation, *string, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceEndpointURL, nil)
	if tag != nil {
		httpRequest.URL.RawQuery = url.Values{"tag": []string{*tag}}.Encode()
	}
	if err != nil {
		return nil, nil, err
	}
	httpResponse, err := h.client.Do(httpRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to invoke remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	defer httpResponse.Body.Close()
	if err := core.TestResponseCode(200, httpResponse); err != nil {
		return nil, nil, fmt.Errorf("non-OK response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	responseData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	var result v1.GetPresentations200JSONResponse
	if err := json.Unmarshal(responseData, &result); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response from remote Discovery Service (url=%s): %w", serviceEndpointURL, err)
	}
	return result.Entries, &result.Tag, nil
}
