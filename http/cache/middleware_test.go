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

package cache

import (
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMaxAge(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/a", nil), httpResponse)

		err := MaxAge(time.Minute, "/a", "/b").Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Equal(t, "max-age=60", httpResponse.Header().Get("Cache-Control"))
	})
	t.Run("no match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/c", nil), httpResponse)

		err := MaxAge(time.Minute, "/a", "/b").Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Empty(t, httpResponse.Header().Get("Cache-Control"))
	})

}

func TestNoCache(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/a", nil), httpResponse)

		err := NoCache("/a", "/b").Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Equal(t, "no-cache", httpResponse.Header().Get("Cache-Control"))
		require.Equal(t, "no-store", httpResponse.Header().Get("Pragma"))
	})
	t.Run("no match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/c", nil), httpResponse)

		err := NoCache("/a", "/b").Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Empty(t, httpResponse.Header().Get("Cache-Control"))
		require.Empty(t, httpResponse.Header().Get("Pragma"))
	})
}
