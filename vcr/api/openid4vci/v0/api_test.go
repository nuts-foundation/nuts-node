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

package v0

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/sirupsen/logrus"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_protocolErrorWriter_Write(t *testing.T) {
	t.Run("not a OpenID4VCI error", func(t *testing.T) {
		hook := &logTest.Hook{}
		logrus.AddHook(hook)
		server := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		echoContext := server.NewContext(req, rec)

		err := protocolErrorWriter{}.Write(echoContext, 0, "", errors.New("something else failed"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.JSONEq(t, `{"error":"server_error"}`, rec.Body.String())
		assert.Equal(t, hook.LastEntry().Message, "OpenID4VCI error occurred (status 500): something else failed")
	})
	t.Run("error is an OpenID4VCI error", func(t *testing.T) {
		hook := &logTest.Hook{}
		logrus.AddHook(hook)
		server := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		echoContext := server.NewContext(req, rec)

		err := protocolErrorWriter{}.Write(echoContext, 0, "", openid4vci.Error{
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusBadRequest,
		})

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.JSONEq(t, `{"error":"invalid_token"}`, rec.Body.String())
		assert.Equal(t, hook.LastEntry().Message, "OpenID4VCI error occurred (status 400): invalid_token")
	})
	t.Run("error is a wrapped OpenID4VCI error", func(t *testing.T) {
		hook := &logTest.Hook{}
		logrus.AddHook(hook)
		server := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		echoContext := server.NewContext(req, rec)

		err := protocolErrorWriter{}.Write(echoContext, 0, "", fmt.Errorf("something went wrong: %w", openid4vci.Error{
			Err:        errors.New("token has expired"),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusBadRequest,
		}))

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.JSONEq(t, `{"error":"invalid_token"}`, rec.Body.String())
		assert.Equal(t, hook.LastEntry().Message, "OpenID4VCI error occurred (status 400): something went wrong: invalid_token - token has expired")
	})
	t.Run("OpenID4VCI error without status code", func(t *testing.T) {
		hook := &logTest.Hook{}
		logrus.AddHook(hook)
		server := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		echoContext := server.NewContext(req, rec)

		err := protocolErrorWriter{}.Write(echoContext, 0, "", openid4vci.Error{
			Code: openid4vci.InvalidToken,
		})

		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.JSONEq(t, `{"error":"invalid_token"}`, rec.Body.String())
		assert.Equal(t, hook.LastEntry().Message, "OpenID4VCI error occurred (status 500): invalid_token")
	})
}
