/*
 * Nuts node
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

package v1

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"schneider.vip/problem"
	"strings"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/didman/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Didman didman.Didman
}

// Routes registers the routes from the open api spec to the echo router.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// AddEndpoint handles calls to add a service. It only checks params and sets the correct return status code.
// didman.AddEndpoint does the heavy lifting.
func (w *Wrapper) AddEndpoint(ctx echo.Context, didStr string) error {
	request := EndpointCreateRequest{}
	if err := ctx.Bind(&request); err != nil {
		return reportProblem(inputError("failed to parse EndpointCreateRequest: %v", err))
	}

	id, err := parseDID(didStr)
	if err != nil {
		return reportProblem(err)
	}

	if len(strings.TrimSpace(request.Type)) == 0 {
		return reportProblem(inputError("invalid value for type"))
	}

	u, err := url.Parse(request.Endpoint)
	if err != nil {
		return reportProblem(inputError("invalid value for endpoint: %v", err))
	}

	if err = w.Didman.AddEndpoint(*id, request.Type, *u); err != nil {
		return reportProblem(err)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// AddCompoundService handles calls to add a compound service. It only checks params and sets the correct return status code.
// didman.AddCompoundService does the heavy lifting.
func (w *Wrapper) AddCompoundService(ctx echo.Context, didStr string) error {
	request := CompoundServiceCreateRequest{}
	if err := ctx.Bind(&request); err != nil {
		return reportProblem(inputError("failed to parse %T: %v", request, err))
	}

	id, err := parseDID(didStr)
	if err != nil {
		return reportProblem(err)
	}

	references := make(map[string]ssi.URI, 0)
	for key, value := range request.Endpoint {
		uri, err := interfaceToURI(value)
		if err != nil {
			return reportProblem(inputError("invalid reference for service '%s': %v", key, err))
		}
		references[key] = *uri
	}
	if err = w.Didman.AddCompoundService(*id, request.Type, references); err != nil {
		return reportProblem(err)
	}
	return ctx.NoContent(http.StatusNoContent)
}

func interfaceToURI(input interface{}) (*ssi.URI, error) {
	str, ok := input.(string)
	if !ok {
		return nil, errors.New("not a string")
	}
	return ssi.ParseURI(str)
}

// DeleteService handles calls to delete a service. It only checks params and sets the correct return status code.
// didman.DeleteService does the heavy lifting.
func (w *Wrapper) DeleteService(ctx echo.Context, uriStr string) error {
	id, err := ssi.ParseURI(uriStr)
	if err != nil {
		return reportProblem(inputError("failed to parse URI: %v", err))
	}

	if err = w.Didman.DeleteService(*id); err != nil {
		return reportProblem(err)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UpdateContactInformation handles requests for updating contact information for a specific DID.
// It parses the did path param and and unmarshals the request body and passes them to didman.UpdateContactInformation.
func (w *Wrapper) UpdateContactInformation(ctx echo.Context, didStr string) error {
	id, err := parseDID(didStr)
	if err != nil {
		return reportProblem(err)
	}

	contactInfo := ContactInformation{}
	if err = ctx.Bind(&contactInfo); err != nil {
		return reportProblem(inputError("failed to parse ContactInformation: %v", err))
	}
	newContactInfo, err := w.Didman.UpdateContactInformation(*id, contactInfo)
	if err != nil {
		return reportProblem(err)
	}

	return ctx.JSON(http.StatusOK, newContactInfo)
}

// GetContactInformation handles requests for contact information for a specific DID.
// It parses the did path param and passes it to didman.GetContactInformation.
func (w *Wrapper) GetContactInformation(ctx echo.Context, didStr string) error {
	id, err := parseDID(didStr)
	if err != nil {
		return reportProblem(err)
	}

	contactInfo, err := w.Didman.GetContactInformation(*id)
	if err != nil {
		return reportProblem(err)
	}
	if contactInfo == nil {
		return reportProblem(notFound("contact information for DID not found"))
	}

	return ctx.JSON(http.StatusOK, contactInfo)
}

func parseDID(didStr string) (*did.DID, error) {
	id, err := did.ParseDID(didStr)
	if err != nil {
		return nil, inputError("failed to parse DID: %v", err)
	}
	return id, nil
}

var errorStatusCodes = map[error]int{
	types.ErrNotFound:                http.StatusNotFound,
	types.ErrDIDNotManagedByThisNode: http.StatusBadRequest,
	types.ErrDeactivated:             http.StatusConflict,
	types.ErrDuplicateService:        http.StatusConflict,
	didman.ErrServiceInUse:           http.StatusConflict,
}

func notFound(errStr string, args ...interface{}) httpStatusCodeError {
	return httpStatusCodeError{msg: fmt.Sprintf(errStr, args...), statusCode: http.StatusNotFound}
}

func inputError(errStr string, args ...interface{}) httpStatusCodeError {
	return httpStatusCodeError{msg: fmt.Sprintf(errStr, args...), statusCode: http.StatusBadRequest}
}

type httpStatusCodeError struct {
	msg        string
	statusCode int
}

func (i httpStatusCodeError) Error() string {
	return i.msg
}

func (i httpStatusCodeError) Is(other error) bool {
	_, is := other.(httpStatusCodeError)
	return is
}

func getStatusCode(err error) int {
	if predefined, ok := err.(httpStatusCodeError); ok {
		return predefined.statusCode
	}
	for curr, code := range errorStatusCodes {
		if errors.Is(err, curr) {
			return code
		}
	}
	return http.StatusInternalServerError
}

// reportProblem logs the given problem with the function name of the caller and returns a problem which can be returned to the calling REST API client.
func reportProblem(err error) *problem.Problem {
	title := fmt.Sprintf("%s failed", getCallerFunctionName(2))
	logging.Log().WithError(err).Warn(title)
	return core.NewProblem(title, getStatusCode(err), err.Error())
}

// getCallerFunctionName looks in the call stack to find the function name, skipping the given number of frames.
// If 0 is passed the returned function name will be getCallerFunctionName,
// if 1 is passed it will be the direct caller of this function and so on.
func getCallerFunctionName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		return ""
	}
	frames := runtime.CallersFrames([]uintptr{pc})
	frame, _ := frames.Next()
	fn := frame.Function
	return fn[strings.LastIndex(fn, ".") + 1:]
}
