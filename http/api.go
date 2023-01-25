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
