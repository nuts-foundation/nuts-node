package v0

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

var _ Protocol = (*S2SVPTokenProtocol)(nil)

// S2SVPTokenProtocol adds support for service-to-service OAuth2 flows,
// which uses a custom vp_token grant to authenticate calls to the token endpoint.
// Clients first call the presentation definition endpoint to get a presentation definition for the desired scope,
// then create a presentation submission given the definition which is posted to the token endpoint as vp_token.
// The AS then returns an access token with the requested scope.
// Requires:
// - GET /presentation_definition?scope=... (returns a presentation definition)
// - POST /token (with vp_token grant)
type S2SVPTokenProtocol struct {
}

func (s S2SVPTokenProtocol) RegisterEndpoints(router OAuth2Server) {
	router.RegisterEndpoint(http.MethodGet, "/presentation_definition", func(echoCtx echo.Context, next func(echo.Context) error) error {
		// TODO: Read scope, map to presentation definition, return
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
	router.RegisterEndpoint(http.MethodGet, "/token", func(echoCtx echo.Context, next func(echo.Context) error) error {
		if echoCtx.FormValue(GrantType) != "vp_token" {
			return next(echoCtx)
		}
		submission := echoCtx.FormValue("presentation_submission")
		scope := echoCtx.FormValue("scope")
		vp_token := echoCtx.FormValue("vp_token")
		if submission == "" || scope == "" || vp_token == "" {
			// TODO: right error response
			return echoCtx.JSON(http.StatusBadRequest, "missing required parameters")
		}
		// TODO: Handle
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
}
