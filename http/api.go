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

package http

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
)

// Preprocess is called by legacy API handlers to preprocess the request.
// It purely exists to deduplicate code that would otherwise be found in all of these API handlers.
func Preprocess(echoContext echo.Context, apiInstance interface{}, moduleName string, operationID string) {
	echoContext.Set(core.StatusCodeResolverContextKey, apiInstance)
	echoContext.Set(core.OperationIDContextKey, operationID)
	echoContext.Set(core.ModuleNameContextKey, moduleName)
	audit.SetOnEchoContext(echoContext, moduleName, operationID)
}
