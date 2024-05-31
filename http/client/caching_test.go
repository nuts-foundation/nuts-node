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
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
	"time"
)

func Test_httpClientCache(t *testing.T) {
	httpRequest := &http.Request{
		Method: http.MethodGet,
		URL:    test.MustParseURL("http://example.com"),
	}
	t.Run("does not cache POST requests", func(t *testing.T) {
		client := NewCachingTransport(&stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "public, max-age=3600",
			},
		}, 1000)

		_, err := client.RoundTrip(&http.Request{
			Method: http.MethodPost,
		})

		require.NoError(t, err)
		assert.Equal(t, 0, client.currentSizeBytes)
	})
	t.Run("caches GET request with max-age", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusCreated,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := NewCachingTransport(requestSink, 1000)

		// Initial fetch
		httpResponse, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, httpResponse.StatusCode)
		fetchedResponseData, _ := io.ReadAll(httpResponse.Body)
		assert.Equal(t, "Hello, World!", string(fetchedResponseData))

		// Fetch the response again, should be taken from cache
		httpResponse, err = client.RoundTrip(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, httpResponse.StatusCode)
		cachedResponseData, _ := io.ReadAll(httpResponse.Body)
		assert.Equal(t, "Hello, World!", string(cachedResponseData))

		assert.Equal(t, 13, client.currentSizeBytes)
		assert.Equal(t, 1, requestSink.invocations)
	})
	t.Run("does not cache responses with no-store", func(t *testing.T) {
		client := NewCachingTransport(&stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "nothing",
			},
		}, 1000)

		_, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, 0, client.currentSizeBytes)
	})
	t.Run("max-age is too long", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": fmt.Sprintf("max-age=%d", int(time.Hour.Seconds()*24)),
			},
		}
		client := NewCachingTransport(requestSink, 1000)

		_, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		assert.LessOrEqual(t, time.Now().Sub(client.head.expirationTime), time.Hour)
	})
	t.Run("2 cache entries with different query parameters", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusOK,
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		requestSink.dataFn = func(req *http.Request) []byte {
			return []byte(req.URL.String())
		}
		client := NewCachingTransport(requestSink, 1000)

		// Initial fetch of the resources
		_, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		alternativeRequest := &http.Request{
			Method: http.MethodGet,
			URL:    test.MustParseURL("http://example.com?foo=bar"),
		}
		_, err = client.RoundTrip(alternativeRequest)
		require.NoError(t, err)
		assert.Equal(t, 2, requestSink.invocations)

		// Fetch the responses again, should be taken from cache
		response1, _ := client.RoundTrip(httpRequest)
		response1Data, _ := io.ReadAll(response1.Body)
		response2, _ := client.RoundTrip(alternativeRequest)
		response2Data, _ := io.ReadAll(response2.Body)
		assert.Equal(t, 2, requestSink.invocations)
		assert.Equal(t, "http://example.com", string(response1Data))
		assert.Equal(t, "http://example.com?foo=bar", string(response2Data))
	})
	t.Run("prunes cache when full", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := NewCachingTransport(requestSink, 14)
		client.insert(&cacheEntry{
			responseData:   []byte("Hello"),
			requestURL:     test.MustParseURL("http://example.com"),
			expirationTime: time.Now().Add(time.Hour),
		})

		_, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, 13, client.currentSizeBytes)
	})
	t.Run("orders entries by expirationTime for optimized pruning", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := NewCachingTransport(requestSink, 10000)
		client.insert(&cacheEntry{
			responseData:   []byte("Hello"),
			requestURL:     test.MustParseURL("http://example.com/3"),
			expirationTime: time.Now().Add(time.Hour * 3),
		})
		assert.Equal(t, client.head.requestURL.String(), "http://example.com/3")
		client.insert(&cacheEntry{
			responseData:   []byte("Hello"),
			requestURL:     test.MustParseURL("http://example.com/2"),
			expirationTime: time.Now().Add(time.Hour * 2),
		})
		assert.Equal(t, client.head.requestURL.String(), "http://example.com/2")
		client.insert(&cacheEntry{
			responseData:   []byte("Hello"),
			requestURL:     test.MustParseURL("http://example.com/1"),
			expirationTime: time.Now().Add(time.Hour),
		})
		assert.Equal(t, client.head.requestURL.String(), "http://example.com/1")
	})
	t.Run("entries that exceed max cache size aren't cached", func(t *testing.T) {
		requestSink := &stubRoundTripper{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := NewCachingTransport(requestSink, 5)

		httpResponse, err := client.RoundTrip(httpRequest)
		require.NoError(t, err)
		data, _ := io.ReadAll(httpResponse.Body)
		assert.Equal(t, "Hello, World!", string(data))
		assert.Equal(t, 0, client.currentSizeBytes)
	})
}

type stubRoundTripper struct {
	statusCode  int
	data        []byte
	dataFn      func(r *http.Request) []byte
	headers     map[string]string
	invocations int
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.invocations++
	response := &http.Response{
		StatusCode: s.statusCode,
	}
	if s.dataFn != nil {
		response.Body = io.NopCloser(bytes.NewReader(s.dataFn(req)))
	} else {
		response.Body = io.NopCloser(bytes.NewReader(s.data))
	}
	response.Header = make(http.Header)
	for key, value := range s.headers {
		response.Header.Set(key, value)
	}
	return response, nil
}
