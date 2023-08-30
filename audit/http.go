/*
 * Copyright (C) 2023 Nuts community
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

package audit

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"strings"
)

// StrictMiddleware is like SetOnEchoContext but then as handler for strict server interfaces.
func StrictMiddleware(next func(ctx echo.Context, args interface{}) (interface{}, error), moduleName, operationID string) func(ctx echo.Context, args interface{}) (interface{}, error) {
	return func(ctx echo.Context, args interface{}) (interface{}, error) {
		SetOnEchoContext(ctx, moduleName, operationID)
		return next(ctx, args)
	}
}

// Middleware is like SetOnEchoContext but then as handler for server interfaces.
// The operation ID is derived from the last part of the request path.
func Middleware(moduleName string) func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			pathParts := strings.Split(c.Request().URL.Path, "/")
			operationID := pathParts[len(pathParts)-1]
			SetOnEchoContext(c, moduleName, operationID)
			return next(c)
		}
	}
}

// SetOnEchoContext adds audit information to the Echo request context so that the audit logger can log it.
// It sets the following fields:
// - actor, which is the subject of the JWT. Falls back to the client IP address if no authentication is used.
// - moduleName, which is the module name of the interface that invoked the operation.
// - operationID, which is operation that invoked the operation.
func SetOnEchoContext(echoCtx echo.Context, moduleName, operationID string) {
	actor := echoCtx.RealIP()
	if user, ok := echoCtx.Get(core.UserContextKey).(string); ok {
		actor = fmt.Sprintf("%s@%s", user, actor)
	}
	ctx := Context(echoCtx.Request().Context(), actor, moduleName, operationID)
	newRequest := echoCtx.Request().WithContext(ctx)
	echoCtx.SetRequest(newRequest)
}
