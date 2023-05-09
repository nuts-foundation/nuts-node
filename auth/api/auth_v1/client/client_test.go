/*
 * Copyright (C) 2021 Nuts community
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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
)

func TestHTTPClient_CreateAccessToken(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		server := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK})
		serverURL, _ := url.Parse(server.URL)

		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(ctx, *serverURL, "bearer_token")

		assert.NotNil(t, response)
		assert.NoError(t, err)
	})

	t.Run("error - non-OK HTTP status code", func(t *testing.T) {
		server := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "Hello, World!"})
		serverURL, _ := url.Parse(server.URL)

		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(ctx, *serverURL, "bearer_token")

		assert.Nil(t, response)
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200)")
		require.Implements(t, new(core.HTTPStatusCodeError), err)
		assert.Equal(t, http.StatusInternalServerError, err.(core.HTTPStatusCodeError).StatusCode())
	})
	t.Run("error - non-OK HTTP status code (large response body)", func(t *testing.T) {
		// Respond with 200 random characters
		responseData := strings.Repeat("a", 200)
		server := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: responseData})
		serverURL, _ := url.Parse(server.URL)

		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(ctx, *serverURL, "bearer_token")

		assert.Nil(t, response)
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200)")
		require.Implements(t, new(core.HTTPStatusCodeError), err)
		assert.Equal(t, http.StatusInternalServerError, err.(core.HTTPStatusCodeError).StatusCode())
	})

	t.Run("error - invalid endpoint", func(t *testing.T) {
		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(ctx, url.URL{}, "bearer_token")

		assert.Nil(t, response)
		assert.Error(t, err)
	})
}
