package irma

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/services/irma"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"strings"
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
		w.Auth.ContractClient().HandlerFunc()(writer, request)
	}
	// wrap the http handler in a echo handler
	irmaEchoHandler := echo.WrapHandler(http.HandlerFunc(rewriteFunc))
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace}
	for _, method := range methods {
		router.Add(method, irma.IrmaMountPath+"/*", irmaEchoHandler)
	}
}
