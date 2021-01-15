/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
	"mime"
	"net/http"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/util"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	C crypto.KeyStore
}

// SignJwt handles api calls for signing a Jwt
func (w *Wrapper) SignJwt(ctx echo.Context) error {
	var signRequest = &SignJwtRequest{}
	err := ctx.Bind(signRequest)
	if err != nil {
		log.Logger().Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(signRequest.Kid) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing kid")
	}

	if len(signRequest.Claims) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing claims")
	}

	sig, err := w.C.SignJWT(signRequest.Claims, signRequest.Kid)

	if err != nil {
		log.Logger().Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return ctx.String(http.StatusOK, sig)
}

// PublicKey returns a public key for the given urn. The urn represents a legal entity. The api returns the public key either in PEM or JWK format.
// It uses the accept header to determine this. Default is PEM (text/plain), only when application/json is requested will it return JWK.
func (w *Wrapper) PublicKey(ctx echo.Context, kid string) error {
	acceptHeader := ctx.Request().Header.Get("Accept")

	pubKey, err := w.C.GetPublicKey(kid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ctx.NoContent(404)
		}
		log.Logger().Error(err.Error())
		return err
	}

	// starts with so we can ignore any +
	if ct, _, _ := mime.ParseMediaType(acceptHeader); ct == "application/json" {
		jwk, err := jwk.New(pubKey)
		if err != nil {
			log.Logger().Error(err.Error())
			return err
		}

		return ctx.JSON(http.StatusOK, jwk)
	}

	// backwards compatible PEM format is the default
	pub, err := util.PublicKeyToPem(pubKey)
	if err != nil {
		log.Logger().Error(err.Error())
		return err
	}

	return ctx.String(http.StatusOK, pub)
}
