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
 */

package v1

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)
var _ core.RoutableWithSpec = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	C crypto.JWTSigner
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		crypto.ErrPrivateKeyNotFound: http.StatusBadRequest,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, w)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, crypto.ModuleName)
}

func (w *Wrapper) Version() int {
	return 1
}

func (w *Wrapper) Name() string {
	return crypto.ModuleName
}

func (w *Wrapper) JsonSpec() ([]byte, error) {
	return rawSpec()
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

func (signRequest SignJwtRequest) validate() error {
	if len(signRequest.Kid) == 0 {
		return errors.New("missing kid")
	}

	if len(signRequest.Claims) == 0 {
		return errors.New("missing claims")
	}

	return nil
}

const (
	problemTitleSignJwt = "SignJWT failed"
)

// SignJwt handles api calls for signing a Jwt
func (w *Wrapper) SignJwt(ctx echo.Context) error {
	var signRequest = &SignJwtRequest{}
	err := ctx.Bind(signRequest)
	if err != nil {
		return err
	}

	if err := signRequest.validate(); err != nil {
		return core.InvalidInputError("invalid sign request: %w", err)
	}

	sig, err := w.C.SignJWT(signRequest.Claims, signRequest.Kid)
	if err != nil {
		return err
	}

	return ctx.String(http.StatusOK, sig)
}
