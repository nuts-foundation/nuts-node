package audit

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
)

// StrictMiddleware is like Middleware but for the strict server interfaces.
func StrictMiddleware(next func(ctx echo.Context, args interface{}) (interface{}, error), moduleName, operationID string) func(ctx echo.Context, args interface{}) (interface{}, error) {
	return func(ctx echo.Context, args interface{}) (interface{}, error) {
		Middleware(ctx, moduleName, operationID)
		return next(ctx, args)
	}
}

// Middleware adds audit information to the Echo request context so that the audit logger can log it.
// It sets the following fields:
// - actor, which is the subject of the JWT. Falls back to the client IP address if no authentication is used.
// - moduleName, which is the module name of the interface that invoked the operation.
// - operationID, which is operation that invoked the operation.
func Middleware(echoCtx echo.Context, moduleName, operationID string) {
	actor := echoCtx.RealIP()
	if user, ok := echoCtx.Get(core.UserContextKey).(string); ok {
		actor = fmt.Sprintf("%s@%s", user, actor)
	}
	ctx := Context(echoCtx.Request().Context(), actor, moduleName, operationID)
	newRequest := echoCtx.Request().WithContext(ctx)
	echoCtx.SetRequest(newRequest)
}
