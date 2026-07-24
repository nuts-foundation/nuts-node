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
	oldStrictMode := StrictMode
	t.Cleanup(func() { StrictMode = oldStrictMode })
	t.Run("caching transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true

			client := NewWithCache(time.Second)
			httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
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

			client := NewWithCache(time.Second)
			httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
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

		client := NewWithCache(time.Second)
		httpRequest, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := client.Do(httpRequest)

		assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
		assert.Equal(t, 0, rt.invocations)
	})
}

func TestStrictHTTPClient_RedirectScheme(t *testing.T) {
	original := tracing.Enabled()
	tracing.SetEnabled(false) // ensure the constructed client uses the raw transport
	t.Cleanup(func() { tracing.SetEnabled(original) })

	// httptest servers bind to loopback, which the strict-mode dial guard blocks. Permit loopback
	// through the allowlist rather than bypassing the guard, so the guard stays active and the
	// redirect scheme check is what must block the plaintext hop.
	oldAllow := allowedNonPublicNets
	require.NoError(t, SetAllowedNonPublicCIDRs([]string{"127.0.0.0/8", "::1/128"}))
	t.Cleanup(func() { allowedNonPublicNets = oldAllow })

	// Plaintext HTTP endpoint the redirect points to.
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// Valid HTTPS remote that redirects the client onto the plaintext endpoint.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Trust the test TLS server via NewWithTLSConfig, a real production constructor.
	tlsConfig := redirector.Client().Transport.(*http.Transport).TLSClientConfig

	setStrictMode := func(t *testing.T, v bool) {
		old := StrictMode
		StrictMode = v
		t.Cleanup(func() { StrictMode = old })
	}

	t.Run("strict mode refuses redirect from HTTPS to HTTP", func(t *testing.T) {
		setStrictMode(t, true)
		reached.Store(false)

		client := NewWithTLSConfig(time.Second, tlsConfig)
		req, _ := http.NewRequest("GET", redirector.URL, nil)
		_, err := client.Do(req)

		assert.Error(t, err, "strict mode must not follow a redirect from HTTPS to HTTP")
		assert.False(t, reached.Load(), "the plaintext endpoint must not be contacted")
	})
	t.Run("non-strict mode follows redirect to HTTP", func(t *testing.T) {
		setStrictMode(t, false)
		reached.Store(false)

		client := NewWithTLSConfig(time.Second, tlsConfig)
		req, _ := http.NewRequest("GET", redirector.URL, nil)
		_, err := client.Do(req)

		assert.NoError(t, err)
		assert.True(t, reached.Load(), "non-strict mode should follow the redirect")
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
