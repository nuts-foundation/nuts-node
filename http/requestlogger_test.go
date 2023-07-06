/*
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

package http

import (
	"bytes"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_requestLoggerMiddleware(t *testing.T) {
	t.Run("it logs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		response := &echo.Response{}
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().NoContent(http.StatusNoContent).Do(func(status int) { response.Status = status })
		echoMock.EXPECT().Request().Return(&http.Request{RequestURI: "/test"})
		echoMock.EXPECT().Response().Return(response)
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := requestLoggerMiddleware(func(c echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		err := logFunc(func(context echo.Context) error {
			return context.NoContent(http.StatusNoContent)
		})(echoMock)

		assert.NoError(t, err)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, "::1", hook.LastEntry().Data["remote_ip"])
		assert.Equal(t, http.StatusNoContent, hook.LastEntry().Data["status"])
		assert.Equal(t, "/test", hook.LastEntry().Data["uri"])
	})

	t.Run("it handles echo.HTTPErrors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := requestLoggerMiddleware(func(_ echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		_ = logFunc(func(context echo.Context) error {
			return echo.NewHTTPError(http.StatusForbidden)
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusForbidden, hook.LastEntry().Data["status"])

	})

	t.Run("it handles httpStatusCodeError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := requestLoggerMiddleware(func(_ echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		_ = logFunc(func(context echo.Context) error {
			return core.NotFoundError("not found")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusNotFound, hook.LastEntry().Data["status"])
	})

	t.Run("it handles go errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := requestLoggerMiddleware(func(_ echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		_ = logFunc(func(context echo.Context) error {
			return errors.New("failed")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusInternalServerError, hook.LastEntry().Data["status"])
	})
}

func Test_bodyLoggerMiddleware(t *testing.T) {
	t.Run("it logs", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		e := echo.New()
		request := httptest.NewRequest("GET", "/", bytes.NewReader([]byte(`"request"`)))
		request.Header.Set("Content-Type", "application/json")
		responseRecorder := httptest.NewRecorder()
		response := echo.NewResponse(responseRecorder, e)
		response.Header().Set("Content-Type", "application/json")
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().NoContent(http.StatusNoContent).Do(func(status int) {
			response.Status = status
			response.Write([]byte(`"response"`))
		})
		echoMock.EXPECT().Request().MinTimes(1).Return(request)
		echoMock.EXPECT().Response().MinTimes(1).Return(response)

		logger, hook := test.NewNullLogger()
		logFunc := bodyLoggerMiddleware(func(c echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		err := logFunc(func(context echo.Context) error {
			return context.NoContent(http.StatusNoContent)
		})(echoMock)

		assert.NoError(t, err)
		assert.Len(t, hook.Entries, 2)
		assert.Equal(t, `HTTP request body: "request"`, hook.AllEntries()[0].Message)
		assert.Equal(t, `HTTP response body: "response"`, hook.AllEntries()[1].Message)
	})
	t.Run("request and response not loggable", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		e := echo.New()
		request := httptest.NewRequest("GET", "/", bytes.NewReader([]byte{1, 2, 3}))
		request.Header.Set("Content-Type", "application/binary")
		responseRecorder := httptest.NewRecorder()
		response := echo.NewResponse(responseRecorder, e)
		response.Header().Set("Content-Type", "application/binary")
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().NoContent(http.StatusNoContent).Do(func(status int) {
			response.Status = status
			response.Write([]byte{1, 2, 3})
		})
		echoMock.EXPECT().Request().MinTimes(1).Return(request)
		echoMock.EXPECT().Response().MinTimes(1).Return(response)

		logger, hook := test.NewNullLogger()
		logFunc := bodyLoggerMiddleware(func(c echo.Context) bool {
			return false
		}, logger.WithFields(logrus.Fields{}))
		err := logFunc(func(context echo.Context) error {
			return context.NoContent(http.StatusNoContent)
		})(echoMock)

		assert.NoError(t, err)
		assert.Len(t, hook.Entries, 2)
		assert.Equal(t, `HTTP request body: (not loggable: application/binary)`, hook.AllEntries()[0].Message)
		assert.Equal(t, `HTTP response body: (not loggable: application/binary)`, hook.AllEntries()[1].Message)
	})
}
