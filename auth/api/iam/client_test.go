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
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHTTPClient_OAuthAuthorizationServerMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("ok using web:did", func(t *testing.T) {
		result := OAuthAuthorizationServerMetadata{TokenEndpoint: "/token"}
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: result}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := stringURLToDID(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		require.NotNil(t, handler.Request)
		assert.Equal(t, "GET", handler.Request.Method)
		assert.Equal(t, fmt.Sprintf("/.well-known/oauth-authorization-server/iam/%s", testDID), handler.Request.URL.Path)
	})
	t.Run("error - non 200 return value", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := stringURLToDID(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
	t.Run("error - bad contents", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "not json"}
		tlsServer, client := testServerAndClient(t, &handler)
		testDID := stringURLToDID(t, tlsServer.URL)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
	t.Run("error - server not responding", func(t *testing.T) {
		_, client := testServerAndClient(t, nil)
		testDID := stringURLToDID(t, "https://localhost:1234")

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, testDID)

		assert.Error(t, err)
		assert.Nil(t, metadata)
	})
}

func testServerAndClient(t *testing.T, handler http.Handler) (*httptest.Server, *HTTPClient) {
	tlsServer := httptest.NewUnstartedServer(handler)
	keyPair, err := tls.LoadX509KeyPair("../../../http/test/cert.pem", "../../../http/test/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	return tlsServer, &HTTPClient{
		httpClient: tlsServer.Client(),
	}
}

func stringURLToDID(t *testing.T, stringUrl string) did.DID {
	asURL, err := url.Parse(stringUrl)
	require.NoError(t, err)
	testDID, err := didweb.URLToDID(*asURL)
	require.NoError(t, err)
	return *testDID
}
