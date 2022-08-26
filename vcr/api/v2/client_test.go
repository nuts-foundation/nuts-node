/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

var didString = "did:nuts:1"
var credentialType = "type"

func TestHttpClient_Trust(t *testing.T) {

	s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNoContent})
	c := &HTTPClient{
		ClientConfig: core.ClientConfig{
			Address: s.URL,
			Timeout: time.Second,
		},
	}
	funcs := []func(string, string) error{
		c.Trust,
		c.Untrust,
	}

	for _, fn := range funcs {
		t.Run("ok", func(t *testing.T) {
			err := fn(credentialType, didString)

			assert.NoError(t, err)
		})

		t.Run("error - other status code", func(t *testing.T) {
			s.Config.Handler = http2.Handler{StatusCode: http.StatusInternalServerError}
			defer func() {
				s.Config.Handler = http2.Handler{StatusCode: http.StatusNoContent}
			}()
			err := fn(credentialType, didString)

			assert.Error(t, err)
		})
	}

	t.Run("trust - error - connection problem", func(t *testing.T) {
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "unknown",
				Timeout: time.Second,
			},
		}

		err := c.Trust(credentialType, didString)

		assert.Error(t, err)
	})

	t.Run("untrust - error - connection problem", func(t *testing.T) {
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "unknown",
				Timeout: time.Second,
			},
		}

		err := c.Untrust(credentialType, didString)

		assert.Error(t, err)
	})
}

func TestHttpClient_Trusted(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
		result := []string{didString}
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: result})
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: s.URL,
				Timeout: time.Second,
			},
		}

		dids, err := c.Trusted(credentialType)

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, dids)
	})

	t.Run("error - not found", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound})
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: s.URL,
				Timeout: time.Second,
			},
		}

		_, err := c.Trusted(credentialType)

		assert.Error(t, err)
	})

	t.Run("error - connection problem", func(t *testing.T) {
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "unknown",
				Timeout: time.Second,
			},
		}

		_, err := c.Trusted(credentialType)

		assert.Error(t, err)
	})

	t.Run("error - wrong content", func(t *testing.T) {
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"})
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: s.URL,
				Timeout: time.Second,
			},
		}

		_, err := c.Trusted(credentialType)

		assert.Error(t, err)
	})
}

func TestHttpClient_Untrusted(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
		result := []string{didString}
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: result})
		c := &HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: s.URL,
				Timeout: time.Second,
			},
		}

		dids, err := c.Untrusted(credentialType)

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, dids)
	})
}
