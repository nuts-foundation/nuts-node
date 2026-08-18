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
	"io"
	"net"
	"net/http"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// SafeHttpTransport is a http.Transport that can be used as a default transport for HTTP clients.
// It carries the strict-mode SSRF dial guard (see denyNonPublicAddr), but only that: the HTTPS
// requirement, the redirect-downgrade check and the response size limit live on StrictHTTPClient.
// Do not build a raw http.Client on this transport for outbound requests; use the New* constructors
// so all strict-mode protections apply.
var SafeHttpTransport *http.Transport

func init() {
	SafeHttpTransport = http.DefaultTransport.(*http.Transport).Clone()
	if SafeHttpTransport.TLSClientConfig == nil {
		SafeHttpTransport.TLSClientConfig = &tls.Config{}
	}
	SafeHttpTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
	// to prevent slow responses from public clients to have significant impact (default was unlimited)
	SafeHttpTransport.MaxConnsPerHost = 5
	// guard against SSRF: in strict mode, refuse to connect to loopback/link-local/
	// unspecified addresses, checked against the resolved IP so DNS-rebinding cannot
	// bypass it. Keeps the default dialer timeouts used by http.DefaultTransport.
	SafeHttpTransport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   denyNonPublicAddr,
	}).DialContext
	// set DefaultCachingTransport to SafeHttpTransport so it is set even when caching is disabled
	DefaultCachingTransport = SafeHttpTransport
}

// httpSpanName formats span names for outbound HTTP requests.
func httpSpanName(_ string, r *http.Request) string {
	return "http-client: " + r.Method + " " + r.URL.Path
}

// StrictMode is a flag that can be set to true to enable strict mode for the HTTP client.
var StrictMode bool

// checkRedirect is the http.Client.CheckRedirect policy for the strict HTTP client.
// Setting CheckRedirect replaces the standard library's default policy, so the
// 10-redirect cap is reimplemented here. It also re-runs core.ParsePublicURLAllowIP on
// every redirect target: the check in Do only guards the first hop, so without this a
// valid remote host could redirect the client onto a plaintext or otherwise disallowed
// endpoint. IP-literal hosts are left to the dial guard (see denyNonPublicAddr), which
// runs on every hop already and is aware of http.client.allowedinternalcidrs/deniedcidrs;
// rejecting them here too would make that allowlist unreachable.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if _, err := core.ParsePublicURLAllowIP(req.URL.String(), StrictMode); err != nil {
		return fmt.Errorf("invalid redirect target: %w", err)
	}
	return nil
}

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
	transport := getTransport(SafeHttpTransport)
	return &StrictHTTPClient{
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: checkRedirect,
		},
	}
}

// getTransport wraps the given transport with request/response logging and OpenTelemetry
// instrumentation (if tracing is enabled).
func getTransport(base http.RoundTripper) http.RoundTripper {
	// Always install the logging transport so logging can be enabled after the client is created:
	// whether to log is decided per request (see loggingTransport), not when the client is created.
	transport := http.RoundTripper(&loggingTransport{base: base})
	if tracing.Enabled() {
		return otelhttp.NewTransport(transport,
			otelhttp.WithSpanNameFormatter(httpSpanName),
			otelhttp.WithTracerProvider(tracing.GetTracerProvider()),
		)
	}
	return transport
}

// NewWithCache creates a new HTTP client with the given timeout.
// It uses the DefaultCachingTransport as the underlying transport.
func NewWithCache(timeout time.Duration) *StrictHTTPClient {
	transport := getTransport(DefaultCachingTransport)
	return &StrictHTTPClient{
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: checkRedirect,
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
			Transport:     getTransport(transport),
			Timeout:       timeout,
			CheckRedirect: checkRedirect,
		},
	}
}

type StrictHTTPClient struct {
	client *http.Client
}

func (s *StrictHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// IP-literal hosts are left to the dial guard (see denyNonPublicAddr): it is aware of
	// http.client.allowedinternalcidrs/deniedcidrs, this check is not.
	if _, err := core.ParsePublicURLAllowIP(req.URL.String(), StrictMode); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
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
