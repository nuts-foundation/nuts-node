package v0

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"net/http"
)

const GrantType = "grant_type"

var _ core.Routable = &OAuth2API{}

// OAuth2API handles OAuth2 flows. It registers flows registering the same endpoints as a chain in reverse order,
// e.g., if OpenID4VP and OpenID4VCI both register an `/authorize` endpoint (in this order), the following call order applies:
// 1. OpenID4VCI
// 2. OpenID4VP
// 3. Default error handler (invalid parameters)
type OAuth2API struct {
	VCR vcr.VCR
}

func (r OAuth2API) Routes(router core.EchoRouter) {
	registrar := endpointRegistrar{
		handlers: map[endpoint]func(echoCtx echo.Context) error{},
		metadata: map[string]interface{}{},
	}

	// Let every protocol register its endpoints
	for _, protocol := range []Protocol{S2SVPTokenProtocol{}, OpenID4VCIProtocol{}} {
		protocol.RegisterEndpoints(registrar)
	}

	for currEndpoint, currHandler := range registrar.handlers {
		router.Add(currEndpoint.method, currEndpoint.path, currHandler)
	}

	// Register common endpoints
	// TODO: Probably not the right URL, but it's a POC
	router.GET("/.well-known/oauth-authorization-server", func(c echo.Context) error {
		return c.JSON(200, registrar.metadata)
	})
}

type endpoint struct {
	method string
	path   string
}

type endpointRegistrar struct {
	handlers map[endpoint]func(echoCtx echo.Context) error
	metadata map[string]interface{}
}

func (e endpointRegistrar) RegisterMetadata(key string, value interface{}) {
	e.metadata[key] = value
}

func (e endpointRegistrar) RegisterEndpoint(method string, path string, handler HandlerFunc) {
	endpointKey := endpoint{
		method: method,
		path:   path,
	}
	prevHandler := e.handlers[endpointKey]
	if prevHandler == nil {
		prevHandler = func(echoCtx echo.Context) error {
			// TODO: alter response type based on request type? (e.g. JSON vs. form)
			// TODO: use oauth2 error code
			return echoCtx.String(http.StatusBadRequest, "Unsupported combination of parameters")
		}
	}
	e.handlers[endpointKey] = func(echoCtx echo.Context) error {
		return handler(echoCtx, prevHandler)
	}
}
