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
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	stdHttp "net/http"
	"testing"
	"time"
)

func TestStrictHTTPClient(t *testing.T) {
	t.Run("caching transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("strict mode disabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = false

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.NoError(t, err)
			assert.Equal(t, 1, rt.invocations)
		})
	})
	t.Run("TLS transport", func(t *testing.T) {
		t.Run("strict mode enabled", func(t *testing.T) {
			rt := &stubRoundTripper{}
			DefaultCachingTransport = rt
			StrictMode = true

			client := NewWithCache(time.Second)
			httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
			_, err := client.Do(httpRequest)

			assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
			assert.Equal(t, 0, rt.invocations)
		})
		t.Run("sets TLS config", func(t *testing.T) {
			client := NewWithTLSConfig(time.Second, &tls.Config{
				InsecureSkipVerify: true,
			})
			ts := client.client.Transport.(*stdHttp.Transport)
			assert.True(t, ts.TLSClientConfig.InsecureSkipVerify)
		})
	})
	t.Run("error on HTTP call when strictmode is enabled", func(t *testing.T) {
		rt := &stubRoundTripper{}
		DefaultCachingTransport = rt
		StrictMode = true

		client := NewWithCache(time.Second)
		httpRequest, _ := stdHttp.NewRequest("GET", "http://example.com", nil)
		_, err := client.Do(httpRequest)

		assert.EqualError(t, err, "strictmode is enabled, but request is not over HTTPS")
		assert.Equal(t, 0, rt.invocations)
	})
}
