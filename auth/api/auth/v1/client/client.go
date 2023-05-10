/*
 * Copyright (C) 2021 Nuts community
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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
)

type oauthAPIError struct {
	err        error
	statusCode int
}

func (err *oauthAPIError) StatusCode() int {
	return err.statusCode
}

func (err *oauthAPIError) Error() string {
	return err.err.Error()
}

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	Timeout time.Duration
	client  ClientInterface
}

// NewHTTPClient creates a new HTTPClient using the generated OAS client
func NewHTTPClient(serverAddress string, timeout time.Duration, opts ...ClientOption) (*HTTPClient, error) {
	client, err := NewClientWithResponses(serverAddress, opts...)
	if err != nil {
		return nil, err
	}

	return &HTTPClient{Timeout: timeout, client: client}, nil
}

// CreateAccessToken creates an access token and overrides the url by the 'endpointURL' input argument
func (h HTTPClient) CreateAccessToken(ctx context.Context, endpointURL url.URL, bearerToken string) (*AccessTokenResponse, error) {
	values := url.Values{}
	values.Set("assertion", bearerToken)
	values.Set("grant_type", JwtBearerGrantType)

	response, err := h.client.CreateAccessTokenWithBody(
		ctx,
		"application/x-www-form-urlencoded",
		strings.NewReader(values.Encode()),
		withURL(endpointURL),
	)
	if err != nil {
		return nil, err
	}

	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		rse := err.(core.HttpError)
		// Cut off the response body to 100 characters max to prevent logging of large responses
		responseBodyString := string(rse.ResponseBody)
		if len(responseBodyString) > 100 {
			responseBodyString = responseBodyString[:100] + "...(clipped)"
		}
		log.Logger().WithError(err).Infof("Erroneous CreateAccessToken response (len=%d): %s", len(rse.ResponseBody), responseBodyString)
		return nil, &oauthAPIError{err: err, statusCode: response.StatusCode}
	}

	result, err := ParseCreateAccessTokenResponse(response)
	if err != nil {
		return nil, err
	}

	return result.JSON200, nil
}

func withURL(uri url.URL) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.URL = &uri
		return nil
	}
}
