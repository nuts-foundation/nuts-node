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
		if echoErr, ok := err.(*echo.HTTPError); ok {
			ctx.Echo().DefaultHTTPErrorHandler(echoErr, ctx)
			return
		}
		title := fmt.Sprintf("%s failed", fmt.Sprintf("%s", ctx.Get(operationIdContextKey)))
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

func NotFoundError(errStr string, args ...interface{}) HTTPStatusCodeError {
	return HTTPStatusCodeError{msg: fmt.Errorf(errStr, args...).Error(), err: getErrArg(args), statusCode: http.StatusNotFound}
}

func InvalidInputError(errStr string, args ...interface{}) HTTPStatusCodeError {
	return HTTPStatusCodeError{msg: fmt.Errorf(errStr, args...).Error(), err: getErrArg(args), statusCode: http.StatusBadRequest}
}

type HTTPStatusCodeError struct {
	msg        string
	statusCode int
	err        error
}

func (e HTTPStatusCodeError) Is(other error) bool {
	_, is := other.(HTTPStatusCodeError)
	return is
}

func (e HTTPStatusCodeError) Unwrap() error {
	return e.err
}

func (e HTTPStatusCodeError) Error() string {
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
// - errors with a predefined status code (HTTPStatusCodeError)
// - from contextStatusCodes, if present
// - from globalStatusCodes, if present
// - if none of the above criteria match, HTTP 500 Internal Server Error is returned.
func getHTTPStatusCode(err error, globalStatusCodes map[error]int, contextStatusCodes map[error]int) int {
	if predefined, ok := err.(HTTPStatusCodeError); ok {
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
