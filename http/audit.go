package http

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
)

// auditMiddleware returns an Echo middleware that adds audit information to the request context so that the audit logger can log it.
// It sets the following fields:
// - actor, which is the subject of the JWT. Falls back to the client IP address if no authentication is used.
// - operation, which is the module name and invoked REST API operation. Falls back to the HTTP request URI if the previous aren't by the API.
func auditMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		actor := c.RealIP()
		if user, ok := c.Get(core.UserContextKey).(string); ok {
			actor = fmt.Sprintf("%s@%s", user, actor)
		}
		ctx := audit.Context(c.Request().Context(), func() audit.Info {
			// Operation falls back to request URI if operationID and ModuleName are not set
			operation := c.Request().RequestURI
			var requestOperationID = c.Get(core.OperationIDContextKey)
			var requestModuleName = c.Get(core.ModuleNameContextKey)
			if requestOperationID != nil && requestModuleName != nil {
				return audit.NewInfo(actor, requestModuleName.(string), requestOperationID.(string))
			}
			return audit.Info{
				Actor:     actor,
				Operation: operation,
			}
		})
		newRequest := c.Request().WithContext(ctx)
		c.SetRequest(newRequest)
		return next(c)
	}
}
