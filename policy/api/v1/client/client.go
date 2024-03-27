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
	"fmt"
	"net/http"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
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

// PresentationDefinitions retrieves the presentation definitions (as MultiPEX) from the presentation definition endpoint for the given scope and authorizer.
func (hb HTTPClient) PresentationDefinitions(ctx context.Context, serverAddress string, authorizer did.DID, scopes string) ([]MultiPEX, error) {
	_, err := core.ParsePublicURL(serverAddress, hb.strictMode)
	if err != nil {
		return nil, err
	}

	client, err := NewClient(serverAddress, WithHTTPClient(hb.httpClient))
	if err != nil {
		return nil, err
	}
	params := &PresentationDefinitionsParams{
		Scope:      scopes,
		Authorizer: authorizer.String(),
	}
	response, err := client.PresentationDefinitions(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if httpErr := core.TestResponseCode(http.StatusOK, response); httpErr != nil {
		return nil, httpErr
	}

	presentationDefinitionResponse, err := ParsePresentationDefinitionsResponse(response)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w", err)
	}

	if presentationDefinitionResponse.JSON200 == nil {
		return make([]MultiPEX, 0), nil
	}

	return *presentationDefinitionResponse.JSON200, nil
}

// Authorized checks if the given request is authorized by the policy backend.
// The AuthorizedRequest contains the information that is needed to check if the request is authorized.
func (hb HTTPClient) Authorized(ctx context.Context, serverAddress string, request AuthorizedRequest) (bool, error) {
	_, err := core.ParsePublicURL(serverAddress, hb.strictMode)
	if err != nil {
		return false, err
	}

	client, err := NewClient(serverAddress, WithHTTPClient(hb.httpClient))
	if err != nil {
		return false, err
	}

	response, err := client.CheckAuthorized(ctx, request)
	if err != nil {
		return false, fmt.Errorf("failed to call endpoint: %w", err)
	}
	if httpErr := core.TestResponseCode(http.StatusOK, response); httpErr != nil {
		return false, httpErr
	}

	authorizedResponse, err := ParseCheckAuthorizedResponse(response)
	if err != nil {
		return false, fmt.Errorf("unable to unmarshal response: %w", err)
	}

	// theoretically, the JSON200 field could be nil. The API should always return a response, so we return it as error.
	if authorizedResponse.JSON200 == nil {
		return false, fmt.Errorf("response is nil")
	}

	return authorizedResponse.JSON200.Authorized, nil
}
