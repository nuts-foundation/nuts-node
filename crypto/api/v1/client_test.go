/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type handler struct {
	statusCode   int
	responseData []byte
}

func (h handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.WriteHeader(h.statusCode)
	writer.Write(h.responseData)
}

var genericError = []byte("failed")

var jwkAsString = `
{
  "kty" : "RSA",
  "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
  "e"   : "AQAB"
}`
var jwkAsBytes = []byte(jwkAsString)

func TestHttpClient_GetPublicKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: jwkAsBytes})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKey("kid")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
	})
	t.Run("error - server returned non-JWK", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/broken.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKey("kid")
		assert.Contains(t, err.Error(), "failed to unmarshal JWK:")
		assert.Nil(t, res)
	})
	t.Run("error - response not HTTP OK", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: genericError})
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKey("kid")
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200), response: failed")
		assert.Nil(t, res)
	})
	t.Run("error - server not running", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK})
		s.Close()
		c := HTTPClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKey("kid")
		assert.Contains(t, err.Error(), "connection refused")
		assert.Nil(t, res)
	})
}
