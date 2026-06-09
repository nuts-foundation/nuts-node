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
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripperFunc adapts a function to an http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestLoggingTransport(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	t.Cleanup(func() { LogRequests = false; LogRequestBodies = false })

	newRequest := func(t *testing.T, body string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://example.com/foo", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	jsonResponse := func(body string) *http.Response {
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}

	t.Run("disabled: nothing is logged", func(t *testing.T) {
		hook.Reset()
		LogRequests = false
		LogRequestBodies = false
		sut := &loggingTransport{base: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return jsonResponse(`{"hello":"world"}`), nil
		})}

		_, err := sut.RoundTrip(newRequest(t, `{"foo":"bar"}`))

		require.NoError(t, err)
		assert.Empty(t, hook.AllEntries())
	})

	t.Run("metadata only", func(t *testing.T) {
		hook.Reset()
		LogRequests = true
		LogRequestBodies = false
		sut := &loggingTransport{base: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return jsonResponse(`{"hello":"world"}`), nil
		})}

		response, err := sut.RoundTrip(newRequest(t, `{"foo":"bar"}`))

		require.NoError(t, err)
		// Body is left intact for the caller
		responseBody, _ := io.ReadAll(response.Body)
		assert.Equal(t, `{"hello":"world"}`, string(responseBody))
		// Request and response metadata (incl. headers) is logged, but no bodies
		entries := hook.AllEntries()
		require.Len(t, entries, 2)
		assert.Equal(t, "HTTP client request", entries[0].Message)
		assert.Equal(t, http.MethodPost, entries[0].Data["method"])
		assert.Equal(t, "https://example.com/foo", entries[0].Data["uri"])
		assert.Contains(t, entries[0].Data, "headers")
		assert.Equal(t, "HTTP client response", entries[1].Message)
		assert.Equal(t, http.StatusOK, entries[1].Data["status"])
		assert.Contains(t, entries[1].Data, "headers")
	})

	t.Run("metadata and body", func(t *testing.T) {
		hook.Reset()
		LogRequests = true
		LogRequestBodies = true
		var sentBody string
		sut := &loggingTransport{base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			// Request body must still be readable by the actual transport
			b, _ := io.ReadAll(r.Body)
			sentBody = string(b)
			return jsonResponse(`{"hello":"world"}`), nil
		})}

		response, err := sut.RoundTrip(newRequest(t, `{"foo":"bar"}`))

		require.NoError(t, err)
		assert.Equal(t, `{"foo":"bar"}`, sentBody)
		responseBody, _ := io.ReadAll(response.Body)
		assert.Equal(t, `{"hello":"world"}`, string(responseBody))
		entries := hook.AllEntries()
		require.Len(t, entries, 4)
		assert.Equal(t, "HTTP client request", entries[0].Message)
		assert.Contains(t, entries[0].Data, "headers")
		assert.Equal(t, "HTTP client request body: {\"foo\":\"bar\"}", entries[1].Message)
		assert.Equal(t, "HTTP client response", entries[2].Message)
		assert.Equal(t, "HTTP client response body: {\"hello\":\"world\"}", entries[3].Message)
	})

	t.Run("masks sensitive headers", func(t *testing.T) {
		hook.Reset()
		LogRequests = true
		LogRequestBodies = false
		sut := &loggingTransport{base: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			header := http.Header{}
			header.Set("Content-Type", "application/json")
			header.Set("WWW-Authenticate", "Bearer realm=\"example\"")
			return &http.Response{StatusCode: http.StatusUnauthorized, Header: header, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})}
		req := newRequest(t, "{}")
		req.Header.Set("Authorization", "Bearer super-secret-token")

		_, err := sut.RoundTrip(req)

		require.NoError(t, err)
		entries := hook.AllEntries()
		requestHeaders := entries[0].Data["headers"].(http.Header)
		assert.Equal(t, []string{"[MASKED]"}, requestHeaders["Authorization"])
		assert.Equal(t, "application/json", requestHeaders.Get("Content-Type"))
		// Response WWW-Authenticate is a challenge, not a credential, so it is not masked.
		responseHeaders := entries[1].Data["headers"].(http.Header)
		assert.Equal(t, "Bearer realm=\"example\"", responseHeaders.Get("WWW-Authenticate"))
	})

	t.Run("body not logged for non-loggable content type", func(t *testing.T) {
		hook.Reset()
		LogRequests = true
		LogRequestBodies = true
		sut := &loggingTransport{base: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			header := http.Header{}
			header.Set("Content-Type", "application/octet-stream")
			return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader("binary"))}, nil
		})}
		req := newRequest(t, "binary")
		req.Header.Set("Content-Type", "application/octet-stream")

		_, err := sut.RoundTrip(req)

		require.NoError(t, err)
		// Only metadata is logged
		entries := hook.AllEntries()
		require.Len(t, entries, 2)
		assert.Equal(t, "HTTP client request", entries[0].Message)
		assert.Equal(t, "HTTP client response", entries[1].Message)
	})

	t.Run("transport error is logged and returned", func(t *testing.T) {
		hook.Reset()
		LogRequests = true
		LogRequestBodies = false
		sut := &loggingTransport{base: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		})}

		_, err := sut.RoundTrip(newRequest(t, ""))

		require.Error(t, err)
		entries := hook.AllEntries()
		require.Len(t, entries, 2)
		assert.Equal(t, "HTTP client request", entries[0].Message)
		assert.Equal(t, "HTTP client request failed", entries[1].Message)
	})
}
