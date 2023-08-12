package v0

import "github.com/labstack/echo/v4"

// Protocol implements a OAuth2 flow, e.g. vp_token service-to-service, OpenID4VCI, OpenID4VP
type Protocol interface {
	RegisterEndpoints(router OAuth2Server)
}

type HandlerFunc func(echoCtx echo.Context, next func(echo.Context) error) error

// OAuth2Server lets protocols interact with the containing OAuth2 server
type OAuth2Server interface {
	RegisterEndpoint(method string, path string, handler HandlerFunc)
	RegisterMetadata(key string, value interface{})
}
