package core

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"net/http"
	"schneider.vip/problem"
)

const statusCodesContextKey = "!!ErrorStatusCodes"
const operationIdContextKey = "!!OperationId"

func createHTTPErrorHandler(routers []Routable) echo.HTTPErrorHandler {
	globalErrorStatusCodes := errorStatusCodesFromRouters(routers)
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
		operationId := ctx.Get(operationIdContextKey)
		title := "Operation failed"
		if operationId != nil {
			title = fmt.Sprintf("%s failed", fmt.Sprintf("%s", operationId))
		}
		statusCode := getHTTPStatusCode(err, globalErrorStatusCodes, errorStatusCodesFromContext(ctx))
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

// NotFoundError returns an error that maps to a HTTP 400 Bad Request.
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

// ErrorStatusCodeMapper defines the API of a type that provides mapping from Go errors to an HTTP status code.
type ErrorStatusCodeMapper interface {
	ErrorStatusCodes() map[error]int
}

// getHTTPStatusCode resolves the HTTP Status Code to be returned from the given error, in this order:
// - errors with a predefined status code (httpStatusCodeError, echo.HTTPError)
// - from contextStatusCodes, if present
// - from globalStatusCodes, if present
// - if none of the above criteria match, HTTP 500 Internal Server Error is returned.
func getHTTPStatusCode(err error, globalStatusCodes map[error]int, contextStatusCodes map[error]int) int {
	if predefined, ok := err.(httpStatusCodeError); ok {
		return predefined.statusCode
	}
	// First lookup in context, then global
	for _, currMap := range []map[error]int{contextStatusCodes, globalStatusCodes} {
		for curr, code := range currMap {
			if errors.Is(err, curr) {
				return code
			}
		}
	}
	return http.StatusInternalServerError
}

func errorStatusCodesFromRouters(routers []Routable) map[error]int {
	// Collect error to HTTP status code mappings from routers
	globalErrorStatusCodes := make(map[error]int, 0)
	for _, router := range routers {
		if mapper, ok := router.(ErrorStatusCodeMapper); ok {
			for err, statusCode := range mapper.ErrorStatusCodes() {
				globalErrorStatusCodes[err] = statusCode
			}
		}
	}
	return globalErrorStatusCodes
}

func errorStatusCodesFromContext(ctx echo.Context) map[error]int {
	interf := ctx.Get(statusCodesContextKey)
	if interf == nil {
		return nil
	}
	asMap, _ := interf.(map[error]int)
	return asMap
}
