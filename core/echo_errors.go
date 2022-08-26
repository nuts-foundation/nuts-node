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
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"schneider.vip/problem"
)

// StatusCodeResolverContextKey contains the key for the Echo context parameter that specifies a custom HTTP status code resolver.
const StatusCodeResolverContextKey = "!!StatusCodeResolver"

// OperationIDContextKey contains the key for the Echo context parameter that specifies the name of the OpenAPI operation being called,
// for logging/error returning.
const OperationIDContextKey = "!!OperationId"

// ModuleNameContextKey contains the key for the Echo context parameter that specifies the module that contains the OpenAPI operation being called,
// for logging/error returning.
const ModuleNameContextKey = "!!ModuleName"

// UserContextKey is the key used to store the user in HTTP contexts.
const UserContextKey = "user"

const unmappedStatusCode = 0

// CreateHTTPErrorHandler returns an Echo HTTPErrorHandler that logs the error withe xtra fields and returns it as a HTTP response.
func CreateHTTPErrorHandler() echo.HTTPErrorHandler {
	return func(err error, ctx echo.Context) {
		// HTTPErrors occur e.g. when a parameter bind fails. We map this to a httpStatusCodeError so its status code
		// and message get directly mapped to a problem.
		if echoErr, ok := err.(*echo.HTTPError); ok {
			err = httpStatusCodeError{
				msg:        fmt.Sprintf("%s", echoErr.Message),
				statusCode: echoErr.Code,
				err:        echoErr,
			}
		}
		operationID := ctx.Get(OperationIDContextKey)
		title := "Operation failed"
		if operationID != nil {
			title = fmt.Sprintf("%s failed", fmt.Sprintf("%s", operationID))
		}
		statusCode := getHTTPStatusCode(err, ctx)
		result := problem.New(problem.Title(title), problem.Status(statusCode), problem.Detail(err.Error()))
		logger := getContextLogger(ctx)
		logMsg := logger.
			WithField("operationID", operationID).
			WithField("requestURI", ctx.Request().RequestURI).
			WithField("user", ctx.Get(UserContextKey)).
			WithError(err)
		if statusCode == http.StatusInternalServerError {
			logMsg.Error(title)
		} else {
			logMsg.Warn(title)
		}
		if !ctx.Response().Committed {
			if _, err := result.WriteTo(ctx.Response()); err != nil {
				logger.Error(err)
			}
		} else {
			logger.
				WithError(err).
				Warn("Unable to send error back to client, response already committed")
		}
	}
}

// Error returns an error that maps to a HTTP status
func Error(statusCode int, errStr string, args ...interface{}) error {
	return httpStatusCodeError{msg: fmt.Errorf(errStr, args...).Error(), err: getErrArg(args), statusCode: statusCode}
}

// NotFoundError returns an error that maps to a HTTP 404 Status Not Found.
func NotFoundError(errStr string, args ...interface{}) error {
	return Error(http.StatusNotFound, errStr, args...)
}

// InvalidInputError returns an error that maps to a HTTP 400 Bad Request.
func InvalidInputError(errStr string, args ...interface{}) error {
	return Error(http.StatusBadRequest, errStr, args...)
}

// PreconditionFailedError returns an error that maps to a HTTP 412 Status Precondition Failed.
func PreconditionFailedError(errStr string, args ...interface{}) error {
	return Error(http.StatusPreconditionFailed, errStr, args...)
}

// HTTPStatusCodeError defines an interface for HTTP errors that includes a HTTP statuscode
type HTTPStatusCodeError interface {
	StatusCode() int
}

type httpStatusCodeError struct {
	msg        string
	statusCode int
	err        error
}

func (e httpStatusCodeError) StatusCode() int {
	return e.statusCode
}

func (e httpStatusCodeError) Is(other error) bool {
	cast, is := other.(httpStatusCodeError)
	if is {
		return cast.statusCode == e.statusCode
	}
	return false
}

func (e httpStatusCodeError) Unwrap() error {
	return e.err
}

func (e httpStatusCodeError) Error() string {
	return e.msg
}

func getErrArg(args []interface{}) error {
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			return err
		}
	}
	return nil
}

// ErrorStatusCodeResolver defines the API of a type that resolves an HTTP status code from a Go error.
type ErrorStatusCodeResolver interface {
	ResolveStatusCode(err error) int
}

// ResolveStatusCode looks tries to find the first error in the given map that satisfies errors.Is() for the given error,
// and returns the associated integer as HTTP status code. If no match is found it returns 0.
func ResolveStatusCode(err error, mapping map[error]int) int {
	for curr, code := range mapping {
		if errors.Is(err, curr) {
			return code
		}
	}
	return unmappedStatusCode
}

// getHTTPStatusCode resolves the HTTP Status Code to be returned from the given error, in this order:
// - errors with a predefined status code (HTTPStatusCodeError, echo.HTTPError)
// - from handler
// - if none of the above criteria match, HTTP 500 Internal Server Error is returned.
func getHTTPStatusCode(err error, ctx echo.Context) int {
	if predefined, ok := err.(HTTPStatusCodeError); ok {
		return predefined.StatusCode()
	}

	statusCodeResolverInterf := ctx.Get(StatusCodeResolverContextKey)
	var result int
	if statusCodeResolverInterf != nil {
		if statusCodeResolver, ok := statusCodeResolverInterf.(ErrorStatusCodeResolver); ok {
			result = statusCodeResolver.ResolveStatusCode(err)
		}
	}
	if result == unmappedStatusCode {
		result = http.StatusInternalServerError
	}
	return result
}

func getContextLogger(ctx echo.Context) *logrus.Entry {
	fields := logrus.Fields{}
	moduleName := ctx.Get(ModuleNameContextKey)
	if moduleName != nil {
		fields[LogFieldModule] = moduleName
	}
	operationID := ctx.Get(OperationIDContextKey)
	if operationID != nil {
		fields["operation"] = operationID
	}
	return logrus.StandardLogger().WithFields(fields)
}
