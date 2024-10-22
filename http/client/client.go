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
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"io"
	"net/http"
	"time"
)

// SafeHttpTransport is a http.Transport that can be used as a default transport for HTTP clients.
var SafeHttpTransport *http.Transport

func init() {
	SafeHttpTransport = http.DefaultTransport.(*http.Transport).Clone()
	if SafeHttpTransport.TLSClientConfig == nil {
		SafeHttpTransport.TLSClientConfig = &tls.Config{}
	}
	SafeHttpTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
	// to prevent slow responses from public clients to have significant impact (default was unlimited)
	SafeHttpTransport.MaxConnsPerHost = 5
	// set DefaultCachingTransport to SafeHttpTransport so it is set even when caching is disabled
	DefaultCachingTransport = SafeHttpTransport
}

// StrictMode is a flag that can be set to true to enable strict mode for the HTTP client.
var StrictMode bool

// DefaultMaxHttpResponseSize is a default maximum size of an HTTP response body that will be read.
// Very large or unbounded HTTP responses can cause denial-of-service, so it's good to limit how much data is read.
// This of course heavily depends on the use case, but 1MB is a reasonable default.
const DefaultMaxHttpResponseSize = 1024 * 1024

// limitedReadAll reads the given reader until the DefaultMaxHttpResponseSize is reached.
// It returns an error if more data is available than DefaultMaxHttpResponseSize.
func limitedReadAll(reader io.Reader) ([]byte, error) {
	result, err := io.ReadAll(io.LimitReader(reader, DefaultMaxHttpResponseSize+1))
	if len(result) > DefaultMaxHttpResponseSize {
		return nil, fmt.Errorf("data to read exceeds max. safety limit of %d bytes", DefaultMaxHttpResponseSize)
	}
	return result, err
}

// New creates a new HTTP client with the given timeout.
func New(timeout time.Duration) *StrictHTTPClient {
	return &StrictHTTPClient{
		client: &http.Client{
			Transport: SafeHttpTransport,
			Timeout:   timeout,
		},
	}
}

// NewWithCache creates a new HTTP client with the given timeout.
// It uses the DefaultCachingTransport as the underlying transport.
func NewWithCache(timeout time.Duration) *StrictHTTPClient {
	return &StrictHTTPClient{
		client: &http.Client{
			Transport: DefaultCachingTransport,
			Timeout:   timeout,
		},
	}
}

// NewWithTLSConfig creates a new HTTP client with the given timeout and TLS configuration.
// It copies the http.DefaultTransport and sets the TLSClientConfig to the given tls.Config.
// As such, it can't be used in conjunction with the CachingRoundTripper.
func NewWithTLSConfig(timeout time.Duration, tlsConfig *tls.Config) *StrictHTTPClient {
	transport := SafeHttpTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	return &StrictHTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

type StrictHTTPClient struct {
	client *http.Client
}

func (s *StrictHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if StrictMode && req.URL.Scheme != "https" {
		return nil, errors.New("strictmode is enabled, but request is not over HTTPS")
	}
	req.Header.Set("User-Agent", core.UserAgent())
	result, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if result.Body != nil {
		body, err := limitedReadAll(result.Body)
		if err != nil {
			return nil, err
		}
		result.Body = io.NopCloser(bytes.NewReader(body))
	}
	return result, nil
}
