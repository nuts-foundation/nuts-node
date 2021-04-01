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
	"mime"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/util"
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
	problemTitleSignJwt   = "SignJWT failed"
	problemTitlePublicKey = "Failed to get PublicKey"
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

// PublicKey returns a public key for the given kid. The urn represents a legal entity. The api returns the public key either in PEM or JWK format.
// It uses the accept header to determine this. Default is PEM (text/plain), only when application/json is requested will it return JWK.
func (w *Wrapper) PublicKey(ctx echo.Context, kid string, params PublicKeyParams) error {
	acceptHeader := ctx.Request().Header.Get(echo.HeaderAccept)

	at := time.Now()
	var err error
	if params.At != nil {
		at, err = time.Parse(time.RFC3339, *params.At)
		if err != nil {
			return core.NewProblem(problemTitlePublicKey, http.StatusBadRequest, fmt.Sprintf("cannot parse '%s' as RFC3339 time format", *params.At))
		}
	}

	pubKey, err := w.C.GetPublicKey(kid, at)
	if err != nil {
		if errors.Is(err, crypto.ErrKeyNotFound) {
			return core.NewProblem(problemTitlePublicKey, http.StatusNotFound, fmt.Sprintf("no public key found for %s", kid))
		}
		log.Logger().Error(err.Error())
		return core.NewProblem(problemTitlePublicKey, http.StatusInternalServerError, err.Error())
	}

	if ct, _, _ := mime.ParseMediaType(acceptHeader); ct == "application/json" {
		jwk, err := jwk.New(pubKey)
		if err != nil {
			log.Logger().Error(err.Error())
			return core.NewProblem(problemTitlePublicKey, http.StatusInternalServerError, err.Error())
		}

		return ctx.JSON(http.StatusOK, jwk)
	}

	// backwards compatible PEM format is the default
	pub, err := util.PublicKeyToPem(pubKey)
	if err != nil {
		log.Logger().Error(err.Error())
		return core.NewProblem(problemTitlePublicKey, http.StatusInternalServerError, err.Error())
	}

	return ctx.String(http.StatusOK, pub)
}
