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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStrictHTTPClient(t *testing.T) {
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
