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

package core

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"schneider.vip/problem"
)

func TestHttpErrorHandler(t *testing.T) {
	err := errors.New("error 2")
	es := echo.New()
	es.HTTPErrorHandler = CreateHTTPErrorHandler()
	server := httptest.NewServer(es)
	client := http.Client{}

	t.Run("is echo HTTPError", func(t *testing.T) {
		f := func(c echo.Context) error {
			err := errors.New("failed")
			return &echo.HTTPError{
				Code:     http.StatusForbidden,
				Message:  err.Error(),
				Internal: err,
			}
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"failed\",\"status\":403,\"title\":\"Operation failed\"}", string(bodyBytes))
	})
	t.Run("code from resolver", func(t *testing.T) {
		f := func(c echo.Context) error {
			c.Set(OperationIDContextKey, "test")
			c.Set(ModuleNameContextKey, "some-module")
			c.Set(StatusCodeResolverContextKey, &stubResolver{})
			return err
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFailedDependency, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"error 2\",\"status\":424,\"title\":\"test failed\"}", string(bodyBytes))
	})
	t.Run("no resolver", func(t *testing.T) {
		f := func(c echo.Context) error {
			c.Set(OperationIDContextKey, "test")
			return errors.New("other error")
		}
		es.Add(http.MethodGet, "/", f)
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, 500, resp.StatusCode)
		assert.Equal(t, problem.ContentTypeJSON, resp.Header.Get("Content-Type"))
		bodyBytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "{\"detail\":\"other error\",\"status\":500,\"title\":\"test failed\"}", string(bodyBytes))
	})
}

func Test_NotFoundError(t *testing.T) {
	err := NotFoundError("failed: %s", "oops").(httpStatusCodeError)
	assert.EqualError(t, err, "failed: oops")
	assert.Equal(t, http.StatusNotFound, err.statusCode)
	assert.ErrorIs(t, err, NotFoundError(""))
}

func Test_InvalidInputError(t *testing.T) {
	err := InvalidInputError("failed: %s", "oops").(httpStatusCodeError)
	assert.EqualError(t, err, "failed: oops")
	assert.Equal(t, http.StatusBadRequest, err.statusCode)
	assert.ErrorIs(t, err, InvalidInputError(""))
}

type stubResolver struct{}

func (s stubResolver) ResolveStatusCode(error) int {
	return http.StatusFailedDependency
}

func TestResolveStatusCode(t *testing.T) {
	t.Run("mapped", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, ResolveStatusCode(io.EOF, map[error]int{io.EOF: http.StatusBadRequest}))
	})
	t.Run("unmapped", func(t *testing.T) {
		assert.Equal(t, unmappedStatusCode, ResolveStatusCode(io.EOF, map[error]int{}))
	})
}
