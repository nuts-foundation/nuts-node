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
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	testHTTP "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPInvoker_Register(t *testing.T) {
	vp := vc.VerifiablePresentation{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
	}
	vpData, _ := vp.MarshalJSON()
	t.Run("ok", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusCreated}
		server := httptest.NewServer(handler)
		client := New(false, time.Minute, server.TLS)

		err := client.Register(context.Background(), server.URL, vp)

		assert.NoError(t, err)
		assert.Equal(t, http.MethodPost, handler.Request.Method)
		assert.Equal(t, "application/json", handler.Request.Header.Get("Content-Type"))
		assert.Equal(t, vpData, handler.RequestData)
	})
	t.Run("non-ok with problem details", func(t *testing.T) {
		server := httptest.NewServer(&testHTTP.Handler{StatusCode: http.StatusBadRequest, ResponseData: `{"title":"missing credentials", "status":400, "detail":"could not resolve DID"}`})
		client := New(false, time.Minute, server.TLS)

		err := client.Register(context.Background(), server.URL, vp)

		assert.ErrorContains(t, err, "non-OK response from remote Discovery Service")
		assert.ErrorContains(t, err, "server returned HTTP status code 400")
		assert.ErrorContains(t, err, "missing credentials: could not resolve DID")
	})
	t.Run("non-ok other", func(t *testing.T) {
		server := httptest.NewServer(&testHTTP.Handler{StatusCode: http.StatusNotFound, ResponseData: `not found`})
		client := New(false, time.Minute, server.TLS)

		err := client.Register(context.Background(), server.URL, vp)

		assert.ErrorContains(t, err, "non-OK response from remote Discovery Service")
		assert.ErrorContains(t, err, "server returned HTTP 404")
		assert.ErrorContains(t, err, "not found")
	})
}

func TestHTTPInvoker_Get(t *testing.T) {
	vp := vc.VerifiablePresentation{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
	}

	t.Run("no timestamp from client", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = map[string]interface{}{
			"seed":      "seed",
			"entries":   map[string]interface{}{"1": vp},
			"timestamp": 1,
		}
		server := httptest.NewServer(handler)
		client := New(false, time.Minute, server.TLS)

		presentations, seed, timestamp, err := client.Get(context.Background(), server.URL, 0)

		assert.NoError(t, err)
		assert.Len(t, presentations, 1)
		assert.Equal(t, "0", handler.RequestQuery.Get("timestamp"))
		assert.Equal(t, 1, timestamp)
		assert.Equal(t, "seed", seed)
	})
	t.Run("timestamp provided by client", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = map[string]interface{}{
			"seed":      "seed",
			"entries":   map[string]interface{}{"1": vp},
			"timestamp": 1,
		}
		server := httptest.NewServer(handler)
		client := New(false, time.Minute, server.TLS)

		presentations, _, timestamp, err := client.Get(context.Background(), server.URL, 1)

		assert.NoError(t, err)
		assert.Len(t, presentations, 1)
		assert.Equal(t, "1", handler.RequestQuery.Get("timestamp"))
		assert.Equal(t, 1, timestamp)
	})
	t.Run("check X-Forwarded-Host header", func(t *testing.T) {
		// custom handler to check the X-Forwarded-Host header
		var capturedRequest *http.Request
		handler := func(writer http.ResponseWriter, request *http.Request) {
			capturedRequest = request
			writer.WriteHeader(http.StatusOK)
			writer.Write([]byte("{}"))
		}
		server := httptest.NewServer(http.HandlerFunc(handler))
		client := New(false, time.Minute, server.TLS)

		_, _, _, err := client.Get(context.Background(), server.URL, 0)

		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(capturedRequest.Header.Get("X-Forwarded-Host"), "127.0.0.1"))
	})
	t.Run("server returns invalid status code", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusInternalServerError, ResponseData: `{"title":"internal server error", "status":500, "detail":"db not found"}`}
		server := httptest.NewServer(handler)
		client := New(false, time.Minute, server.TLS)

		_, _, _, err := client.Get(context.Background(), server.URL, 0)

		assert.ErrorContains(t, err, "non-OK response from remote Discovery Service")
		assert.ErrorContains(t, err, "server returned HTTP status code 500")
		assert.ErrorContains(t, err, "internal server error: db not found")
	})
	t.Run("server does not return JSON", func(t *testing.T) {
		handler := &testHTTP.Handler{StatusCode: http.StatusOK}
		handler.ResponseData = "not json"
		server := httptest.NewServer(handler)
		client := New(false, time.Minute, server.TLS)

		_, _, _, err := client.Get(context.Background(), server.URL, 0)

		assert.ErrorContains(t, err, "failed to unmarshal response from remote Discovery Service")
	})
}
