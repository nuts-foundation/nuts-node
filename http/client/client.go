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
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

func init() {
	httpTransport := http.DefaultTransport.(*http.Transport)
	if httpTransport.TLSClientConfig == nil {
		httpTransport.TLSClientConfig = &tls.Config{}
	}
	httpTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
}

// StrictMode is a flag that can be set to true to enable strict mode for the HTTP client.
var StrictMode bool

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
	transport := http.DefaultTransport.(*http.Transport).Clone()
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
	return s.client.Do(req)
}
