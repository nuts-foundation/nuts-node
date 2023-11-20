/*
 * Copyright (C) 2023 Nuts community
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
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClient_PresentationDefinition(t *testing.T) {
	ctx := context.Background()
	authorizer := did.MustParseDID("did:web:example.com")
	definition := pe.PresentationDefinition{
		Id: "123",
	}

	t.Run("ok", func(t *testing.T) {
		var capturedRequest *http.Request
		handler := func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/presentation_definition":
				capturedRequest = request
				writer.WriteHeader(http.StatusOK)
				bytes, _ := json.Marshal(definition)
				writer.Write(bytes)
			}
			writer.WriteHeader(http.StatusNotFound)
		}
		tlsServer, client := testServerAndClient(t, http.HandlerFunc(handler))

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, authorizer, "test")

		require.NoError(t, err)
		require.NotNil(t, definition)
		assert.Equal(t, definition, *response)
		require.NotNil(t, capturedRequest)
		assert.Equal(t, "GET", capturedRequest.Method)
		assert.Equal(t, "/presentation_definition", capturedRequest.URL.Path)
		// check query params
		require.NotNil(t, capturedRequest.URL.Query().Get("scope"))
		assert.Equal(t, "test", capturedRequest.URL.Query().Get("scope"))
		require.NotNil(t, capturedRequest.URL.Query().Get("authorizer"))
		assert.Equal(t, authorizer.String(), capturedRequest.URL.Query().Get("authorizer"))
	})
	t.Run("error - not found", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, authorizer, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 404 (expected: 200)")
		assert.Nil(t, response)
	})
	t.Run("error - invalid URL", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		_, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, ":", authorizer, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
		assert.Nil(t, response)
	})
	t.Run("error - invalid response", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, authorizer, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "unable to unmarshal response: invalid character '}' looking for beginning of value")
		assert.Nil(t, response)
	})
}

func TestHTTPClient_Authorized(t *testing.T) {
	ctx := context.Background()
	audience := did.MustParseDID("did:web:example.com:audience")
	request := AuthorizedRequest{
		Audience:               audience.String(),
		ClientId:               "did:web:example.com:client",
		PresentationSubmission: PresentationSubmission{},
		RequestMethod:          "GET",
		RequestUrl:             "/resource",
		Scope:                  "test 1 2 3",
		Vps:                    nil,
	}

	t.Run("ok", func(t *testing.T) {
		var capturedRequest *http.Request
		var capturedRequestBody []byte
		handler := func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/authorized":
				capturedRequest = request
				capturedRequestBody, _ = io.ReadAll(request.Body)
				writer.WriteHeader(http.StatusOK)
				writer.Write([]byte("true"))
			}
			writer.WriteHeader(http.StatusNotFound)
		}
		tlsServer, client := testServerAndClient(t, http.HandlerFunc(handler))

		response, err := client.Authorized(ctx, tlsServer.URL, request)

		require.NoError(t, err)
		assert.True(t, response)
		require.NotNil(t, capturedRequest)
		assert.Equal(t, "POST", capturedRequest.Method)
		assert.Equal(t, "/authorized", capturedRequest.URL.Path)
		// check body
		require.NotNil(t, capturedRequest.Body)
		var capturedRequestData AuthorizedRequest
		err = json.Unmarshal(capturedRequestBody, &capturedRequestData)
		require.NoError(t, err)
		assert.Equal(t, request, capturedRequestData)
	})
	t.Run("error - not found", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.Authorized(ctx, tlsServer.URL, request)

		require.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 404 (expected: 200)")
		assert.False(t, response)
	})
	t.Run("error - invalid URL", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		_, client := testServerAndClient(t, &handler)

		response, err := client.Authorized(ctx, ":", request)

		require.Error(t, err)
		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
		assert.False(t, response)
	})
	t.Run("error - invalid response", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.Authorized(ctx, tlsServer.URL, request)

		require.Error(t, err)
		assert.EqualError(t, err, "unable to unmarshal response: invalid character '}' looking for beginning of value")
		assert.False(t, response)
	})
	t.Run("error - invalid endpoint", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK}
		_, client := testServerAndClient(t, &handler)

		response, err := client.Authorized(ctx, "http://::1:1", request)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to call endpoint: Post \"http://::1:1/authorized\": dial tcp [::1]:1: connect: connection refused")
		assert.False(t, response)
	})
}

func testServerAndClient(t *testing.T, handler http.Handler) (*httptest.Server, *HTTPClient) {
	tlsServer := http2.TestTLSServer(t, handler)
	return tlsServer, &HTTPClient{
		httpClient: tlsServer.Client(),
	}
}
