/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/log"
)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	C crypto.KeyStore
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
		log.Logger().Error(err.Error())
		return core.NewProblem(problemTitleSignJwt, http.StatusBadRequest, err.Error())
	}

	if err := signRequest.validate(); err != nil {
		return core.NewProblem(problemTitleSignJwt, http.StatusBadRequest, err.Error())
	}

	sig, err := w.C.SignJWT(signRequest.Claims, signRequest.Kid)
	if err != nil {
		if errors.Is(err, crypto.ErrKeyNotFound) {
			return core.NewProblem(problemTitleSignJwt, http.StatusBadRequest, fmt.Sprintf("no private key found for %s", signRequest.Kid))
		}
		log.Logger().Error(err.Error())
		return core.NewProblem(problemTitleSignJwt, http.StatusInternalServerError, err.Error())
	}

	return ctx.String(http.StatusOK, sig)
}
