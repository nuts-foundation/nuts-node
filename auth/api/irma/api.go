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

package irma

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/services/irma"
	"github.com/nuts-foundation/nuts-node/core"
)

// Wrapper bridges Echo routes to the server backend.
type Wrapper struct {
	Auth auth.AuthenticationServices
}

// Routes registers the Echo routes for the API.
func (w Wrapper) Routes(router core.EchoRouter) {
	// The Irma router operates on the mount path and does not know about the prefix.
	rewriteFunc := func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, irma.IrmaMountPath) {
			// strip the prefix
			request.URL.Path = strings.Split(request.URL.Path, irma.IrmaMountPath)[1]
		}
		w.Auth.ContractNotary().HandlerFunc()(writer, request)
	}
	// wrap the http handler in a echo handler
	irmaEchoHandler := echo.WrapHandler(http.HandlerFunc(rewriteFunc))
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace}
	for _, method := range methods {
		router.Add(method, irma.IrmaMountPath+"/*", irmaEchoHandler)
	}
}
