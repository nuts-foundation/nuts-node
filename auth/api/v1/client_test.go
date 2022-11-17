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

package v1

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
)

func TestHTTPClient_CreateAccessToken(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		server := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK})
		serverURL, _ := url.Parse(server.URL)

		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(*serverURL, "bearer_token")

		assert.NotNil(t, response)
		assert.NoError(t, err)
	})

	t.Run("error_internal_server_error", func(t *testing.T) {
		server := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError})
		serverURL, _ := url.Parse(server.URL)

		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(*serverURL, "bearer_token")

		assert.Nil(t, response)
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200), response: null")
		require.Implements(t, new(core.HTTPStatusCodeError), err)
		assert.Equal(t, http.StatusInternalServerError, err.(core.HTTPStatusCodeError).StatusCode())
	})

	t.Run("error_invalid_endpoint", func(t *testing.T) {
		client, _ := NewHTTPClient("", time.Second)

		response, err := client.CreateAccessToken(url.URL{}, "bearer_token")

		assert.Nil(t, response)
		assert.Error(t, err)
	})
}
