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
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

// HttpResponseBodyLogClipAt is the maximum length of a response body to log.
// If the response body is longer than this, it will be truncated.
const HttpResponseBodyLogClipAt = 200

// HttpError describes an error returned when invoking a remote server.
type HttpError struct {
	error
	StatusCode   int
	ResponseBody []byte
}

// TestResponseCode checks whether the returned HTTP status response code matches the expected code.
// If it doesn't match it returns an error, containing the received and expected status code, and the response body.
func TestResponseCode(expectedStatusCode int, response *http.Response) error {
	return TestResponseCodeWithLog(expectedStatusCode, response, nil)
}

// TestResponseCodeWithLog acts like TestResponseCode, but logs the response body if the status code is not as expected.
// It logs using the given logger, unless nil is passed.
func TestResponseCodeWithLog(expectedStatusCode int, response *http.Response, log *logrus.Entry) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := io.ReadAll(response.Body)
		if log != nil {
			// Cut off the response body to 100 characters max to prevent logging of large responses
			responseBodyString := string(responseData)
			if len(responseBodyString) > HttpResponseBodyLogClipAt {
				responseBodyString = responseBodyString[:HttpResponseBodyLogClipAt] + "...(clipped)"
			}
			log.WithField("http_request_path", response.Request.URL.Path).
				Infof("Unexpected HTTP response (len=%d): %s", len(responseData), responseBodyString)
		}
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

// CreateHTTPInternalClient creates a new HTTP client with the given client configuration.
// This client is to be used for internal API calls (CMDs and such)
// The result HTTPRequestDoer can be supplied to OpenAPI generated clients for executing requests.
// This does not use the generated client options for e.g. authentication,
// because each generated OpenAPI client reimplements the client options using structs,
// which makes them incompatible with each other, making it impossible to use write generic client code for common traits like authorization.
// If the given authorization token builder is non-nil, it calls it and passes the resulting token as bearer token with requests.
func CreateHTTPInternalClient(cfg ClientConfig, generator AuthorizationTokenGenerator) (HTTPRequestDoer, error) {
	var result *httpRequestDoerAdapter
	client := &http.Client{}
	client.Timeout = cfg.Timeout

	result = &httpRequestDoerAdapter{
		fn: client.Do,
	}

	if generator == nil {
		// Add auth interceptor if configured
		authToken, err := cfg.GetAuthToken()
		if err != nil {
			return nil, err
		}

		if len(authToken) > 0 {
			generator = newLegacyTokenGenerator(authToken)
		}
	}

	if generator == nil {
		generator = newEmptyTokenGenerator()
	}

	fn := result.fn
	result = &httpRequestDoerAdapter{fn: func(req *http.Request) (*http.Response, error) {
		token, err := generator()
		if err != nil {
			return nil, fmt.Errorf("failed to generate authorization token: %w", err)
		}
		if len(token) > 0 {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return fn(req)
	}}

	return result, nil
}

// MustCreateInternalHTTPClient is like CreateHTTPInternalClient but panics if it returns an error.
func MustCreateInternalHTTPClient(cfg ClientConfig, generator AuthorizationTokenGenerator) HTTPRequestDoer {
	client, err := CreateHTTPInternalClient(cfg, generator)
	if err != nil {
		panic(err)
	}
	return client
}

// AuthorizationTokenGenerator is a function type definition for creating authorization tokens
type AuthorizationTokenGenerator func() (string, error)

func newLegacyTokenGenerator(token string) AuthorizationTokenGenerator {
	return func() (string, error) {
		return token, nil
	}
}

func newEmptyTokenGenerator() AuthorizationTokenGenerator {
	return func() (string, error) {
		return "", nil
	}
}
