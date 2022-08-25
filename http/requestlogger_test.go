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
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func Test_loggerMiddleware(t *testing.T) {
	t.Run("it logs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		response := &echo.Response{}
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().NoContent(http.StatusNoContent).Do(func(status int) { response.Status = status })
		echoMock.EXPECT().Request().Return(&http.Request{RequestURI: "/test"})
		echoMock.EXPECT().Response().Return(response)
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		err := logFunc(func(context echo.Context) error {
			return context.NoContent(http.StatusNoContent)
		})(echoMock)

		assert.NoError(t, err)
		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, "::1", hook.LastEntry().Data["remote_ip"])
		assert.Equal(t, http.StatusNoContent, hook.LastEntry().Data["status"])
		assert.Equal(t, "/test", hook.LastEntry().Data["uri"])
		ctrl.Finish()
	})

	t.Run("it handles echo.HTTPErrors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return echo.NewHTTPError(http.StatusForbidden)
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusForbidden, hook.LastEntry().Data["status"])
		ctrl.Finish()

	})

	t.Run("it handles httpStatusCodeError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return core.NotFoundError("not found")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusNotFound, hook.LastEntry().Data["status"])
		ctrl.Finish()
	})

	t.Run("it handles go errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoMock := mock.NewMockContext(ctrl)
		echoMock.EXPECT().Request().Return(&http.Request{})
		echoMock.EXPECT().Response().Return(&echo.Response{Status: http.StatusOK})
		echoMock.EXPECT().RealIP().Return("::1")

		logger, hook := test.NewNullLogger()
		logFunc := loggerMiddleware(loggerConfig{logger: logger.WithFields(logrus.Fields{})})
		_ = logFunc(func(context echo.Context) error {
			return errors.New("failed")
		})(echoMock)

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, http.StatusInternalServerError, hook.LastEntry().Data["status"])
		ctrl.Finish()
	})
}

//
//func Test_skipLogRequest(t *testing.T) {
//	req := &http.Request{}
//	ctx := echo.New().NewContext(req, nil)
//	t.Run("matches", func(t *testing.T) {
//		req.RequestURI = "/status"
//		assert.True(t, skipLogRequest(ctx))
//		req.RequestURI = "/metrics"
//		assert.True(t, skipLogRequest(ctx))
//	})
//	t.Run("no match", func(t *testing.T) {
//		req.RequestURI = "/status/"
//		assert.False(t, skipLogRequest(ctx))
//		req.RequestURI = "/status/foo"
//		assert.False(t, skipLogRequest(ctx))
//		req.RequestURI = "/foobar"
//		assert.False(t, skipLogRequest(ctx))
//	})
//}
