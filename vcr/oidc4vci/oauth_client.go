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

package oidc4vci

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Client defines a generic OAuth2 client.
type OAuth2Client interface {
	// RequestAccessToken requests an access token from the Authorization Server.
	RequestAccessToken(grantType string, params map[string]string) (*TokenResponse, error)
}

var _ OAuth2Client = &httpOAuth2Client{}

type httpOAuth2Client struct {
	metadata   ProviderMetadata
	httpClient *http.Client
}

func (c httpOAuth2Client) RequestAccessToken(grantType string, params map[string]string) (*TokenResponse, error) {
	values := url.Values{}
	values.Add("grant_type", grantType)
	for key, value := range params {
		values.Add(key, value)
	}
	httpRequest, _ := http.NewRequestWithContext(context.Background(), "POST", c.metadata.TokenEndpoint, strings.NewReader(values.Encode()))
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	var accessTokenResponse TokenResponse
	err := httpDo(c.httpClient, httpRequest, &accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("request access token error: %w", err)
	}
	return &accessTokenResponse, nil
}
