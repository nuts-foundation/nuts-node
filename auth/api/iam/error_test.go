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
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		assert.EqualError(t, OAuth2Error{InternalError: errors.New("token has expired"), Code: InvalidRequest}, "invalid_request - token has expired")
	})
	t.Run("without underlying error", func(t *testing.T) {
		assert.EqualError(t, OAuth2Error{Code: InvalidRequest}, "invalid_request")
	})
}

func Test_oauth2ErrorWriter_Write(t *testing.T) {
	t.Run("user-agent is browser with redirect URI", func(t *testing.T) {
		server := echo.New()
		httpRequest := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := server.NewContext(httpRequest, rec)

		err := oauth2ErrorWriter{}.Write(ctx, 0, "", OAuth2Error{
			Code:        InvalidRequest,
			Description: "failure",
			RedirectURI: "https://example.com",
		})

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "https://example.com?error=invalid_request&error_description=failure", rec.Header().Get("Location"))
	})
	t.Run("user-agent is browser without redirect URI", func(t *testing.T) {
		server := echo.New()
		httpRequest := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := server.NewContext(httpRequest, rec)

		err := oauth2ErrorWriter{}.Write(ctx, 0, "", OAuth2Error{
			Code:        InvalidRequest,
			Description: "failure",
		})

		assert.NoError(t, err)
		body, _ := io.ReadAll(rec.Body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "text/plain; charset=UTF-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "invalid_request - failure", string(body))
		assert.Empty(t, rec.Header().Get("Location"))
	})
	t.Run("user-agent is API client (sent JSON)", func(t *testing.T) {
		server := echo.New()
		httpRequest := httptest.NewRequest("GET", "/", nil)
		httpRequest.Header["Content-Type"] = []string{"application/json"}
		rec := httptest.NewRecorder()
		ctx := server.NewContext(httpRequest, rec)

		err := oauth2ErrorWriter{}.Write(ctx, 0, "", OAuth2Error{
			Code:        InvalidRequest,
			Description: "failure",
		})

		assert.NoError(t, err)
		body, _ := io.ReadAll(rec.Body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "application/json; charset=UTF-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, `{"error":"invalid_request","error_description":"failure"}`, strings.TrimSpace(string(body)))
		assert.Empty(t, rec.Header().Get("Location"))
	})
	t.Run("OAuth2 error without code, defaults to server_error", func(t *testing.T) {
		server := echo.New()
		httpRequest := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := server.NewContext(httpRequest, rec)

		err := oauth2ErrorWriter{}.Write(ctx, 0, "", OAuth2Error{
			Description: "failure",
		})

		assert.NoError(t, err)
		body, _ := io.ReadAll(rec.Body)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, `server_error - failure`, strings.TrimSpace(string(body)))
	})
	t.Run("error is not an OAuth2 error, should be wrapped", func(t *testing.T) {
		server := echo.New()
		httpRequest := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := server.NewContext(httpRequest, rec)

		err := oauth2ErrorWriter{}.Write(ctx, 0, "", errors.New("catastrophic"))

		assert.NoError(t, err)
		body, _ := io.ReadAll(rec.Body)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, `server_error`, strings.TrimSpace(string(body)))
	})
}
