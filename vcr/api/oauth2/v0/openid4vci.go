package v0

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

const PreAuthorizedCode = "pre-authorized_code"

// OpenID4VCIProtocol adds support for issuing Verifiable Credentials using OpenID Connect.
// Requires:
// - GET /.well-known/openid-configuration (returns an OpenID Connect discovery document)
// - /
type OpenID4VCIProtocol struct {
}

func (p OpenID4VCIProtocol) RegisterEndpoints(router OAuth2Server) {
	router.RegisterEndpoint(http.MethodGet, "/token", func(echoCtx echo.Context, next func(echo.Context) error) error {
		if echoCtx.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			return next(echoCtx)
		}
		code := echoCtx.FormValue(PreAuthorizedCode)
		if code == "" {
			// TODO: right error response
			return echoCtx.JSON(http.StatusBadRequest, "missing required parameter")
		}
		// TODO: handle
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
	router.RegisterEndpoint(http.MethodGet, "/credential", func(echoCtx echo.Context, next func(echo.Context) error) error {
		// TODO: handle
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
}
