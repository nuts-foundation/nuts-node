package core

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"net/http"
	"schneider.vip/problem"
)

const statusCodeResolverContextKey = "!!StatusCodeResolver"
const operationIDContextKey = "!!OperationId"
const unmappedStatusCode = 0

func createHTTPErrorHandler() echo.HTTPErrorHandler {
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
		operationID := ctx.Get(operationIDContextKey)
		title := "Operation failed"
		if operationID != nil {
			title = fmt.Sprintf("%s failed", fmt.Sprintf("%s", operationID))
		}
		statusCode := getHTTPStatusCode(err, ctx)
		result := problem.New(problem.Title(title), problem.Status(statusCode), problem.Detail(err.Error()))
		if statusCode == http.StatusInternalServerError {
			logging.Log().WithError(err).Error(title)
		} else {
			logging.Log().WithError(err).Warn(title)
		}
		if !ctx.Response().Committed {
			if _, err := result.WriteTo(ctx.Response()); err != nil {
				ctx.Echo().Logger.Error(err)
			}
		} else {
			ctx.Echo().Logger.Warnf("Unable to send error back to client, response already committed: %v", err)
		}
	}
}

// NotFoundError returns an error that maps to a HTTP 404 Status Not Found.
func NotFoundError(errStr string, args ...interface{}) error {
	return httpStatusCodeError{msg: fmt.Errorf(errStr, args...).Error(), err: getErrArg(args), statusCode: http.StatusNotFound}
}

// InvalidInputError returns an error that maps to a HTTP 400 Bad Request.
func InvalidInputError(errStr string, args ...interface{}) error {
	return httpStatusCodeError{msg: fmt.Errorf(errStr, args...).Error(), err: getErrArg(args), statusCode: http.StatusBadRequest}
}

type httpStatusCodeError struct {
	msg        string
	statusCode int
	err        error
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
// - errors with a predefined status code (httpStatusCodeError, echo.HTTPError)
// - from handler
// - if none of the above criteria match, HTTP 500 Internal Server Error is returned.
func getHTTPStatusCode(err error, ctx echo.Context) int {
	if predefined, ok := err.(httpStatusCodeError); ok {
		return predefined.statusCode
	}

	statusCodeResolverInterf := ctx.Get(statusCodeResolverContextKey)
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
