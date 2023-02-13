/*
 * Nuts node
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

package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// HttpError describes an error returned when invoking a remote server.
type HttpError struct {
	error
	StatusCode   int
	ResponseBody []byte
}

// TestResponseCode checks whether the returned HTTP status response code matches the expected code.
// If it doesn't match it returns an error, containing the received and expected status code, and the response body.
func TestResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := io.ReadAll(response.Body)
		return HttpError{
			error:        fmt.Errorf("server returned HTTP %d (expected: %d)", response.StatusCode, expectedStatusCode),
			StatusCode:   response.StatusCode,
			ResponseBody: responseData,
		}
	}
	return nil
}

// UserAgentRequestEditor can be used as request editor function for generated OpenAPI clients,
// to set the HTTP User-Agent header to identify the Nuts node.
func UserAgentRequestEditor(_ context.Context, req *http.Request) error {
	req.Header.Set("User-Agent", UserAgent())
	return nil
}

// HTTPRequestDoer defines the Do method of the http.Client interface.
type HTTPRequestDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// httpRequestDoerAdapter wraps a HTTPRequestFn in a struct, so it can be used where HTTPRequestDoer is required.
type httpRequestDoerAdapter struct {
	fn func(req *http.Request) (*http.Response, error)
}

// Do calls the wrapped HTTPRequestFn.
func (w httpRequestDoerAdapter) Do(req *http.Request) (*http.Response, error) {
	return w.fn(req)
}

// CreateHTTPClient creates a new HTTP client with the given client configuration.
// The result HTTPRequestDoer can be supplied to OpenAPI generated clients for executing requests.
// This does not use the generated client options for e.g. authentication,
// because each generated OpenAPI client reimplements the client options using structs,
// which makes them incompatible with each other, making it impossible to use write generic client code for common traits like authorization.
func CreateHTTPClient(cfg ClientConfig, builder AuthorizationTokenBuilder) (HTTPRequestDoer, error) {
	var result *httpRequestDoerAdapter
	client := &http.Client{}
	client.Timeout = cfg.Timeout
	result = &httpRequestDoerAdapter{
		fn: client.Do,
	}

	if builder == nil {
		// Add auth interceptor if configured
		authToken, err := cfg.GetAuthToken()
		if err != nil {
			return nil, err
		}

		if len(authToken) > 0 {
			builder = legacyTokenBuilder{token: authToken}

		}
	}

	if builder == nil {
		builder = noAuth{}
	}

	fn := result.fn
	result = &httpRequestDoerAdapter{fn: func(req *http.Request) (*http.Response, error) {
		token := builder.Create()
		if len(token) > 0 {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return fn(req)
	}}

	return result, nil
}

// MustCreateHTTPClient is like CreateHTTPClient but panics if it returns an error.
func MustCreateHTTPClient(cfg ClientConfig, builder AuthorizationTokenBuilder) HTTPRequestDoer {
	client, err := CreateHTTPClient(cfg, builder)
	if err != nil {
		panic(err)
	}
	return client
}

// AuthorizationTokenBuilder holds methods for creating a bearer token for an HTTP request
type AuthorizationTokenBuilder interface {
	Create() string
}

type legacyTokenBuilder struct {
	token string
}

func (ltb legacyTokenBuilder) Create() string {
	return ltb.token
}

type noAuth struct {
}

func (atb noAuth) Create() string {
	return ""
}
