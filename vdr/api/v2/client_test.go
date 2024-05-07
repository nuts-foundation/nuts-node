/*
 * Nuts node
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

package v2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient_Create(t *testing.T) {
	didDoc := did.Document{
		ID: vdr.TestDIDA,
	}

	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: didDoc})
		c := getClient(s.URL)
		doc, err := c.Create(CreateDIDOptions{})
		require.NoError(t, err)
		assert.NotNil(t, doc)
	})

	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := getClient(s.URL)
		_, err := c.Create(CreateDIDOptions{})
		assert.Error(t, err)
	})

	t.Run("error - wrong address", func(t *testing.T) {
		c := getClient("not_an_address")
		_, err := c.Create(CreateDIDOptions{})
		assert.Error(t, err)
	})
}

func getClient(url string) *HTTPClient {
	return &HTTPClient{
		ClientConfig: core.ClientConfig{
			Address: url, Timeout: time.Second,
		},
	}
}
