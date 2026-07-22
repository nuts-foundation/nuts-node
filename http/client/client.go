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
	"syscall"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

// denyNonPublicAddr is a net.Dialer.Control hook. In strict mode it refuses
// connections whose resolved address is on a network that is never a valid
// outbound federation target: loopback, link-local (which includes the cloud
// metadata address 169.254.169.254) or unspecified. Because it inspects the
// actual IP the socket is about to connect to (after DNS resolution), it closes
// DNS-rebinding into those ranges, which URL-string validation such as
// core.ParsePublicURL cannot.
//
// Private (RFC1918) and unique local (ULA) addresses are deliberately allowed:
// nodes legitimately federate over private networks. Those ranges are guarded by
// the HTTPS-per-hop check (checkRedirect) and the truststore, which require any
// internal target to serve HTTPS with a trusted certificate before a request can
// complete.
func denyNonPublicAddr(_ string, address string, _ syscall.RawConn) error {
	if !StrictMode {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	// The Control hook runs after DNS resolution, so host is a literal IP.
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("strictmode: cannot parse connection address %q", address)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("strictmode: blocked connection to non-public address %s", ip)
	}
	return nil
}

// checkRedirect is the http.Client.CheckRedirect policy for the strict HTTP client.
// Setting CheckRedirect replaces the standard library's default policy, so the
// 10-redirect cap is reimplemented here. In strict mode it also refuses to follow
// a redirect to a non-HTTPS target: the HTTPS check in Do only guards the first
// hop, and the dialer guard sees only the resolved IP and not the scheme, so
// without this a valid remote host could redirect the client onto a plaintext
// internal endpoint.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if StrictMode && req.URL.Scheme != "https" {
		return errors.New("strictmode is enabled, but redirect target is not over HTTPS")
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

// getTransport wraps the given transport with OpenTelemetry instrumentation if tracing is enabled.
func getTransport(base http.RoundTripper) http.RoundTripper {
	if tracing.Enabled() {
		return otelhttp.NewTransport(base,
			otelhttp.WithSpanNameFormatter(httpSpanName),
			otelhttp.WithTracerProvider(tracing.GetTracerProvider()),
		)
	}
	return base
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
