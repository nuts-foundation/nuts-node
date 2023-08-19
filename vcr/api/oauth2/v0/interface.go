package v0

import (
	"github.com/nuts-foundation/nuts-node/core"
)

// authzResponse is the response to an Authorization Code flow request.
type authzResponse struct {
	// html is the HTML page to be rendered to the user.
	html []byte
}

type protocol interface {
	core.Routable
	// handleAuthzRequest handles an Authorization Code flow request and returns an authzResponse if the request is handled by this protocol.
	// If the protocol can't handle the supplied parameters it returns nil.
	handleAuthzRequest(map[string]string, *Session) (*authzResponse, error)
	grantHandlers() map[string]grantHandler
}

// grantHandler defines a function for checking a grant given the input parameters, used to validate token requests.
// It returns the requested scopes if the validation succeeds.
type grantHandler func(map[string]string) (string, error)
