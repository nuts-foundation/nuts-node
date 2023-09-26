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
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"mime"
	"net/http"
)

// requestLoggerMiddleware returns middleware that logs metadata of HTTP requests.
// Should be added as the outer middleware to catch all errors and potential status rewrites
func requestLoggerMiddleware(skipper middleware.Skipper, logger *logrus.Entry) echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper:     skipper,
		LogURI:      true,
		LogStatus:   true,
		LogMethod:   true,
		LogRemoteIP: true,
		LogError:    true,
		LogValuesFunc: func(c echo.Context, values middleware.RequestLoggerValues) error {
			status := values.Status
			if values.Error != nil {
				// In case the error provides `func StatusCode() int`
				// (e.g. core.HTTPStatusCodeError)
				if x, ok := values.Error.(interface{ StatusCode() int }); ok {
					status = x.StatusCode()
				} else if x, ok := values.Error.(*echo.HTTPError); ok {
					status = x.Code
				} else {
					status = http.StatusInternalServerError
				}
			}

			logger.WithFields(logrus.Fields{
				"remote_ip": values.RemoteIP,
				"method":    values.Method,
				"uri":       values.URI,
				"status":    status,
			}).Info("HTTP request")

			return nil
		},
	})
}

// bodyLoggerMiddleware returns middleware that logs body of HTTP requests and their replies.
// Should be added as the outer middleware to catch all errors and potential status rewrites
func bodyLoggerMiddleware(skipper middleware.Skipper, logger *logrus.Entry) echo.MiddlewareFunc {
	return middleware.BodyDumpWithConfig(middleware.BodyDumpConfig{
		Handler: func(e echo.Context, request []byte, response []byte) {
			requestContentType := e.Request().Header.Get("Content-Type")
			requestBody := "(not loggable: " + requestContentType + ")"
			if isLoggableContentType(requestContentType) {
				requestBody = string(request)
			}

			responseContentType := e.Response().Header().Get("Content-Type")
			responseBody := "(not loggable: " + responseContentType + ")"
			if isLoggableContentType(responseContentType) {
				responseBody = string(response)
			}

			logger.Infof("HTTP request body: %s", requestBody)
			logger.Infof("HTTP response body: %s", responseBody)
		},
		Skipper: skipper,
	})
}

func isLoggableContentType(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/json":
		fallthrough
	case "application/did+json":
		fallthrough
	case "application/vc+json":
		fallthrough
	case "application/x-www-form-urlencoded":
		return true
	}
	return false
}
