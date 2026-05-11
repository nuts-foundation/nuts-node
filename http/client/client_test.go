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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrictHTTPClient(t *testing.T) {
	t.Run("caching transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true
			t.Cleanup(func() { StrictMode = false })

			client := NewWithCache(time.Second)
			httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.ErrorContains(t, err, "httpclient: invalid target URL")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("strict mode disabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = false

			client := NewWithCache(time.Second)
			httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.NoError(t, err)
			assert.Equal(t, 1, rt.invocations)
		})
	})
	t.Run("TLS transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true
			t.Cleanup(func() { StrictMode = false })

			client := NewWithCache(time.Second)
			httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.ErrorContains(t, err, "httpclient: invalid target URL")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("sets TLS config", func(t *testing.T) {
			original := tracing.Enabled()
			tracing.SetEnabled(false) // ensure we can cast to *http.Transport
			t.Cleanup(func() { tracing.SetEnabled(original) })
			client := NewWithTLSConfig(time.Second, &tls.Config{
				InsecureSkipVerify: true,
			})
			ts := client.client.Transport.(*http.Transport)
			assert.True(t, ts.TLSClientConfig.InsecureSkipVerify)
		})
	})
	t.Run("error on HTTP call when strictmode is enabled", func(t *testing.T) {
		rt := &stubRoundTripper{}
		DefaultCachingTransport = rt
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })

		client := NewWithCache(time.Second)
		httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := client.Do(httpRequest)

		assert.ErrorContains(t, err, "httpclient: invalid target URL")
		assert.Equal(t, 0, rt.invocations)
	})
	t.Run("strict mode rejects IP host", func(t *testing.T) {
		rt := &stubRoundTripper{}
		DefaultCachingTransport = rt
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })

		client := NewWithCache(time.Second)
		httpRequest, _ := http.NewRequest("GET", "https://127.0.0.1/foo", nil)
		_, err := client.Do(httpRequest)

		assert.ErrorContains(t, err, "httpclient: invalid target URL")
		assert.ErrorContains(t, err, "hostname is IP")
		assert.Equal(t, 0, rt.invocations)
	})
	t.Run("strict mode rejects RFC2606 reserved host", func(t *testing.T) {
		rt := &stubRoundTripper{}
		DefaultCachingTransport = rt
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })

		client := NewWithCache(time.Second)
		httpRequest, _ := http.NewRequest("GET", "https://service.localhost/foo", nil)
		_, err := client.Do(httpRequest)

		assert.ErrorContains(t, err, "httpclient: invalid target URL")
		assert.ErrorContains(t, err, "hostname is RFC2606 reserved")
		assert.Equal(t, 0, rt.invocations)
	})
}

func TestCheckRedirect(t *testing.T) {
	makeReq := func(target string) *http.Request {
		req, _ := http.NewRequest("GET", target, nil)
		return req
	}
	t.Run("strict mode rejects http redirect", func(t *testing.T) {
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })
		err := checkRedirect(makeReq("http://example.org"), nil)
		assert.ErrorContains(t, err, "invalid redirect target")
		assert.ErrorContains(t, err, "scheme must be https")
	})
	t.Run("strict mode rejects redirect to IP host", func(t *testing.T) {
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })
		err := checkRedirect(makeReq("https://127.0.0.1/x"), nil)
		assert.ErrorContains(t, err, "invalid redirect target")
		assert.ErrorContains(t, err, "hostname is IP")
	})
	t.Run("strict mode rejects redirect to reserved host", func(t *testing.T) {
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })
		err := checkRedirect(makeReq("https://internal.localhost/x"), nil)
		assert.ErrorContains(t, err, "invalid redirect target")
		assert.ErrorContains(t, err, "hostname is RFC2606 reserved")
	})
	t.Run("non-strict mode allows http redirect", func(t *testing.T) {
		StrictMode = false
		err := checkRedirect(makeReq("http://example.org"), nil)
		assert.NoError(t, err)
	})
	t.Run("non-strict mode allows redirect to IP host", func(t *testing.T) {
		StrictMode = false
		err := checkRedirect(makeReq("http://127.0.0.1/x"), nil)
		assert.NoError(t, err)
	})
	t.Run("redirect cap stops after 10 hops", func(t *testing.T) {
		StrictMode = false
		via := make([]*http.Request, maxRedirects)
		err := checkRedirect(makeReq("http://example.org"), via)
		assert.ErrorContains(t, err, "stopped after 10 redirects")
	})
	t.Run("cap checked before URL validation", func(t *testing.T) {
		// Even an invalid target should produce the cap error first when via is at the limit.
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })
		via := make([]*http.Request, maxRedirects)
		err := checkRedirect(makeReq("http://example.org"), via)
		assert.ErrorContains(t, err, "stopped after 10 redirects")
	})
}

// redirectOnceTransport is a stub RoundTripper that responds with a 302 to redirectTo
// on the first request, then a 200 OK on subsequent requests. It also counts hops so
// tests can verify the redirected request was (or was not) sent.
type redirectOnceTransport struct {
	redirectTo string
	requests   []*http.Request
}

func (t *redirectOnceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests = append(t.requests, req)
	if len(t.requests) == 1 {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{t.redirectTo}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

// TestStrictHTTPClient_RedirectEndToEnd drives the full net/http redirect path
// through a stub transport so we prove the configured CheckRedirect actually
// fires and blocks the second HTTP request from being issued.
//
// Initial URLs use "nuts.nl" because strict mode rejects RFC 2606 reserved 2LDs
// (example.com/net/org), and the test needs the initial Do() to pass so the
// redirect can be exercised. The hostname is never resolved — the stub
// transport intercepts all requests.
func TestStrictHTTPClient_RedirectEndToEnd(t *testing.T) {
	const initialURL = "https://nuts.nl/"
	t.Run("strict mode blocks redirect to non-https target", func(t *testing.T) {
		rt := &redirectOnceTransport{redirectTo: "http://example.com/x"}
		DefaultCachingTransport = rt
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })

		c := NewWithCache(time.Second)
		req, _ := http.NewRequest("GET", initialURL, nil)
		_, err := c.Do(req)

		require.Error(t, err)
		assert.ErrorContains(t, err, "invalid redirect target")
		assert.ErrorContains(t, err, "scheme must be https")
		// only the initial request reached the transport; the redirect was blocked
		assert.Len(t, rt.requests, 1, "second request must not be issued")
	})
	t.Run("strict mode blocks redirect to IP host", func(t *testing.T) {
		rt := &redirectOnceTransport{redirectTo: "https://10.0.0.1/x"}
		DefaultCachingTransport = rt
		StrictMode = true
		t.Cleanup(func() { StrictMode = false })

		c := NewWithCache(time.Second)
		req, _ := http.NewRequest("GET", initialURL, nil)
		_, err := c.Do(req)

		require.Error(t, err)
		assert.ErrorContains(t, err, "invalid redirect target")
		assert.ErrorContains(t, err, "hostname is IP")
		assert.Len(t, rt.requests, 1)
	})
	t.Run("non-strict mode follows http redirect", func(t *testing.T) {
		rt := &redirectOnceTransport{redirectTo: "http://example.com/x"}
		DefaultCachingTransport = rt
		StrictMode = false

		c := NewWithCache(time.Second)
		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		resp, err := c.Do(req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Len(t, rt.requests, 2, "both initial and redirected request should be issued")
	})
}

func TestLimitedReadAll(t *testing.T) {
	t.Run("less than limit", func(t *testing.T) {
		data := strings.Repeat("a", 10)
		result, err := limitedReadAll(strings.NewReader(data))

		assert.NoError(t, err)
		assert.Equal(t, []byte(data), result)
	})
	t.Run("more than limit", func(t *testing.T) {
		data := strings.Repeat("a", DefaultMaxHttpResponseSize+1)
		result, err := limitedReadAll(strings.NewReader(data))

		assert.EqualError(t, err, "data to read exceeds max. safety limit of 1048576 bytes")
		assert.Nil(t, result)
	})
}

func TestMaxConns(t *testing.T) {
	oldStrictMode := StrictMode
	StrictMode = false
	t.Cleanup(func() { StrictMode = oldStrictMode })
	// Our safe http Transport has MaxConnsPerHost = 5
	// if we request 6 resources multiple times, we expect a max connection usage of 5

	// counter for the number of concurrent requests
	var counter atomic.Int32

	// create a test server with 6 different url handlers
	handler := http.NewServeMux()
	createHandler := func(id int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			counter.Add(1)
			assert.True(t, counter.Load() < 6)
			_, _ = w.Write([]byte(fmt.Sprintf("%d", id)))
			time.Sleep(time.Millisecond) // to allow for some parallel requests
			counter.Add(-1)
		}
	}
	handler.HandleFunc("/1", createHandler(1))
	handler.HandleFunc("/2", createHandler(2))
	handler.HandleFunc("/3", createHandler(3))
	handler.HandleFunc("/4", createHandler(4))
	handler.HandleFunc("/5", createHandler(5))
	handler.HandleFunc("/6", createHandler(6))

	server := httptest.NewServer(handler)
	defer server.Close()
	client := New(time.Second)

	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, _ := http.NewRequest("GET", fmt.Sprintf("%s/%d", server.URL, i%6), nil)
			_, _ = client.Do(request)
		}()
	}

	wg.Wait()
}

func TestCaching(t *testing.T) {
	oldStrictMode := StrictMode
	StrictMode = false
	t.Cleanup(func() { StrictMode = oldStrictMode })
	// counter for the number of concurrent requests
	var total atomic.Int32

	// create a test server with 6 different url handlers
	handler := http.NewServeMux()
	createHandler := func(id int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			total.Add(1)
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", 5))
			_, _ = w.Write([]byte(fmt.Sprintf("%d", id)))
		}
	}
	handler.HandleFunc("/1", createHandler(1))

	server := httptest.NewServer(handler)
	defer server.Close()
	DefaultCachingTransport = NewCachingTransport(SafeHttpTransport, 1024*1024)
	client := NewWithCache(time.Second)

	// fill cache
	request, _ := http.NewRequest("GET", fmt.Sprintf("%s/1", server.URL), nil)
	_, err := client.Do(request)
	require.NoError(t, err)

	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("%s/1", server.URL), nil)
			_, _ = client.Do(req)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), total.Load())
}

func TestGetTransport(t *testing.T) {
	t.Run("wraps transport when tracing enabled", func(t *testing.T) {
		original := tracing.Enabled()
		tracing.SetEnabled(true)
		t.Cleanup(func() { tracing.SetEnabled(original) })

		transport := getTransport(SafeHttpTransport)

		// Should not be the same as SafeHttpTransport (it's wrapped)
		assert.NotEqual(t, SafeHttpTransport, transport)
	})

	t.Run("returns base transport when tracing disabled", func(t *testing.T) {
		original := tracing.Enabled()
		tracing.SetEnabled(false)
		t.Cleanup(func() { tracing.SetEnabled(original) })

		transport := getTransport(SafeHttpTransport)

		assert.Equal(t, SafeHttpTransport, transport)
	})
}

func TestNew(t *testing.T) {
	t.Run("wraps transport when tracing enabled", func(t *testing.T) {
		original := tracing.Enabled()
		tracing.SetEnabled(true)
		t.Cleanup(func() { tracing.SetEnabled(original) })

		client := New(time.Second)

		// Transport should be wrapped (not equal to SafeHttpTransport)
		assert.NotEqual(t, SafeHttpTransport, client.client.Transport)
	})

	t.Run("uses SafeHttpTransport when tracing disabled", func(t *testing.T) {
		original := tracing.Enabled()
		tracing.SetEnabled(false)
		t.Cleanup(func() { tracing.SetEnabled(original) })

		client := New(time.Second)

		assert.Equal(t, SafeHttpTransport, client.client.Transport)
	})
}
