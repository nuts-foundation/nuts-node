package iam

import (
	"bytes"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
)

func Test_httpClientCache(t *testing.T) {
	httpRequest := &http.Request{
		Method: http.MethodGet,
		URL:    test.MustParseURL("http://example.com"),
	}
	t.Run("does not cache POST requests", func(t *testing.T) {
		client := cacheHTTPResponses(&stubRequestDoer{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "public, max-age=3600",
			},
		})

		_, err := client.Do(&http.Request{
			Method: http.MethodPost,
		})

		require.NoError(t, err)
		assert.Equal(t, 0, client.currentSizeBytes)
	})
	t.Run("caches GET request with max-age", func(t *testing.T) {
		requestSink := &stubRequestDoer{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := cacheHTTPResponses(requestSink)

		httpResponse, err := client.Do(httpRequest)
		require.NoError(t, err)
		fetchedResponseData, _ := io.ReadAll(httpResponse.Body)
		httpResponse, err = client.Do(httpRequest)
		require.NoError(t, err)
		cachedResponseData, _ := io.ReadAll(httpResponse.Body)

		assert.Equal(t, 13, client.currentSizeBytes)
		assert.Equal(t, 1, requestSink.invocations)
		assert.Equal(t, "Hello, World!", string(fetchedResponseData))
		assert.Equal(t, "Hello, World!", string(cachedResponseData))
	})
	t.Run("2 cache entries with different query parameters", func(t *testing.T) {
		requestSink := &stubRequestDoer{
			statusCode: http.StatusOK,
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		requestSink.dataFn = func(req *http.Request) []byte {
			return []byte(req.URL.String())
		}
		client := cacheHTTPResponses(requestSink)

		// Initial fetch of the resources
		_, err := client.Do(httpRequest)
		require.NoError(t, err)
		alternativeRequest := &http.Request{
			Method: http.MethodGet,
			URL:    test.MustParseURL("http://example.com?foo=bar"),
		}
		_, err = client.Do(alternativeRequest)
		require.NoError(t, err)
		assert.Equal(t, 2, requestSink.invocations)

		// Fetch the responses again, should be taken from cache
		response1, _ := client.Do(httpRequest)
		response1Data, _ := io.ReadAll(response1.Body)
		response2, _ := client.Do(alternativeRequest)
		response2Data, _ := io.ReadAll(response2.Body)
		assert.Equal(t, 2, requestSink.invocations)
		assert.Equal(t, "http://example.com", string(response1Data))
		assert.Equal(t, "http://example.com?foo=bar", string(response2Data))
	})
	t.Run("prunes cache when full", func(t *testing.T) {
		requestSink := &stubRequestDoer{
			statusCode: http.StatusOK,
			data:       []byte("Hello, World!"),
			headers: map[string]string{
				"Cache-Control": "max-age=3600",
			},
		}
		client := cacheHTTPResponses(requestSink)
		client.MaxBytes = 14
		client.currentSizeBytes = 1

		// Fill the cache
		_, err := client.Do(httpRequest)
		require.NoError(t, err)
		_, err = client.Do(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, 13, client.currentSizeBytes)

		// Add a new entry, should prune the first one
		_, err = client.Do(httpRequest)
		require.NoError(t, err)
		assert.Equal(t, 13, client.currentSizeBytes)
		assert.Equal(t, 2, requestSink.invocations)
	})
}

type stubRequestDoer struct {
	statusCode  int
	data        []byte
	dataFn      func(r *http.Request) []byte
	headers     map[string]string
	invocations int
}

func (s *stubRequestDoer) Do(req *http.Request) (*http.Response, error) {
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
