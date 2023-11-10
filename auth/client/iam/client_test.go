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

package iam

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHTTPClient_OAuthAuthorizationServerMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("ok using root web:did", func(t *testing.T) {
		result := oauth.AuthorizationServerMetadata{TokenEndpoint: "/token"}
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: result}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := didweb.ServerURLToDIDWeb(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		require.NotNil(t, handler.Request)
		assert.Equal(t, "GET", handler.Request.Method)
		assert.Equal(t, "/.well-known/oauth-authorization-server", handler.Request.URL.Path)
	})
	t.Run("ok using user web:did", func(t *testing.T) {
		result := oauth.AuthorizationServerMetadata{TokenEndpoint: "/token"}
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: result}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := didweb.ServerURLToDIDWeb(t, tlsServer.URL)
		testDID = did.MustParseDID(testDID.String() + ":iam:123")

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		require.NotNil(t, handler.Request)
		assert.Equal(t, "GET", handler.Request.Method)
		assert.Equal(t, "/.well-known/oauth-authorization-server/iam/123", handler.Request.URL.Path)
	})
	t.Run("error - non 200 return value", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := didweb.ServerURLToDIDWeb(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
	t.Run("error - bad contents", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "not json"}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := didweb.ServerURLToDIDWeb(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
	t.Run("error - server not responding", func(t *testing.T) {
		_, client := testServerAndClient(t, nil)
		testDID := didweb.ServerURLToDIDWeb(t, "https://localhost:1234")

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
}

func TestHTTPClient_PresentationDefinition(t *testing.T) {
	ctx := context.Background()
	definition := pe.PresentationDefinition{
		Id: "123",
	}

	t.Run("ok", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: definition}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, "test")

		require.NoError(t, err)
		require.NotNil(t, definition)
		assert.Equal(t, definition, *response)
		require.NotNil(t, handler.Request)
	})
	t.Run("ok - multiple scopes", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: definition}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, "first second")

		require.NoError(t, err)
		require.NotNil(t, definition)
		assert.Equal(t, definition, *response)
		require.NotNil(t, handler.Request)
		assert.Equal(t, url.Values{"scope": []string{"first second"}}, handler.Request.URL.Query())
	})
	t.Run("error - invalid_scope", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: oauth.OAuth2Error{Code: oauth.InvalidScope}}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "invalid_scope")
		assert.Nil(t, response)
	})
	t.Run("error - not found", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 404 (expected: 200)")
		assert.Nil(t, response)
	})
	t.Run("error - invalid URL", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		_, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, ":", "test")

		require.Error(t, err)
		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
		assert.Nil(t, response)
	})
	t.Run("error - unknown host", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound}
		_, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, "http://localhost", "test")

		require.Error(t, err)
		assert.ErrorContains(t, err, "connection refused")
		assert.Nil(t, response)
	})
	t.Run("error - invalid response", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.PresentationDefinition(ctx, tlsServer.URL, "test")

		require.Error(t, err)
		assert.EqualError(t, err, "unable to unmarshal response: invalid character '}' looking for beginning of value")
		assert.Nil(t, response)
	})
}

func TestHTTPClient_AccessToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		now := int(time.Now().Unix())
		scope := "test"
		accessToken := oauth.TokenResponse{
			AccessToken: "token",
			TokenType:   "bearer",
			Scope:       &scope,
			ExpiresIn:   &now,
		}
		vp := vc.VerifiablePresentation{}

		t.Run("ok", func(t *testing.T) {
			handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: accessToken}
			tlsServer, client := testServerAndClient(t, &handler)

			response, err := client.AccessToken(ctx, tlsServer.URL, vp, pe.PresentationSubmission{}, "test")

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, "token", response.AccessToken)
			assert.Equal(t, "bearer", response.TokenType)
			require.NotNil(t, response.Scope)
			assert.Equal(t, "test", *response.Scope)
			require.NotNil(t, response.ExpiresIn)
			assert.Equal(t, now, *response.ExpiresIn)
		})
	})
	t.Run("error - oauth error", func(t *testing.T) {
		ctx := context.Background()
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: oauth.OAuth2Error{Code: oauth.InvalidScope}}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "test")

		require.Error(t, err)
		// check if the error is a http error
		httpError, ok := err.(core.HttpError)
		require.True(t, ok)
		assert.Equal(t, "{\"error\":\"invalid_scope\"}", string(httpError.ResponseBody))
	})
	t.Run("error - generic server error", func(t *testing.T) {
		ctx := context.Background()
		handler := http2.Handler{StatusCode: http.StatusBadGateway, ResponseData: "offline"}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, vc.VerifiablePresentation{}, pe.PresentationSubmission{}, "test")

		require.Error(t, err)
		// check if the error is a http error
		httpError, ok := err.(core.HttpError)
		require.True(t, ok)
		assert.Equal(t, "offline", string(httpError.ResponseBody))
	})
}

func testServerAndClient(t *testing.T, handler http.Handler) (*httptest.Server, *HTTPClient) {
	tlsServer := http2.TestTLSServer(t, handler)
	return tlsServer, &HTTPClient{
		httpClient: tlsServer.Client(),
	}
}
