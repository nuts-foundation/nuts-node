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
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
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
			if len(responseBodyString) > 100 {
				responseBodyString = responseBodyString[:100] + "...(clipped)"
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

// CreateHTTPClient creates a new HTTP client with the given client configuration.
// The result HTTPRequestDoer can be supplied to OpenAPI generated clients for executing requests.
// This does not use the generated client options for e.g. authentication,
// because each generated OpenAPI client reimplements the client options using structs,
// which makes them incompatible with each other, making it impossible to use write generic client code for common traits like authorization.
// If the given authorization token builder is non-nil, it calls it and passes the resulting token as bearer token with requests.
func CreateHTTPClient(cfg ClientConfig, generator AuthorizationTokenGenerator) (HTTPRequestDoer, error) {
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

// MustCreateHTTPClient is like CreateHTTPClient but panics if it returns an error.
func MustCreateHTTPClient(cfg ClientConfig, generator AuthorizationTokenGenerator) HTTPRequestDoer {
	client, err := CreateHTTPClient(cfg, generator)
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

// NewStrictHTTPClient creates a HTTPRequestDoer that only allows HTTPS calls when strictmode is enabled.
func NewStrictHTTPClient(strictmode bool, timeout time.Duration, tlsConfig *tls.Config) *StrictHTTPClient {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	transport := http.DefaultTransport
	// Might not be http.Transport in testing
	if httpTransport, ok := transport.(*http.Transport); ok {
		// cloning the transport might reduce performance.
		httpTransport = httpTransport.Clone()
		httpTransport.TLSClientConfig = tlsConfig
		transport = httpTransport
	}

	return &StrictHTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		strictMode: strictmode,
	}
}

type StrictHTTPClient struct {
	client     *http.Client
	strictMode bool
}

func (s *StrictHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if s.strictMode && req.URL.Scheme != "https" {
		return nil, errors.New("strictmode is enabled, but request is not over HTTPS")
	}
	return s.client.Do(req)
}
