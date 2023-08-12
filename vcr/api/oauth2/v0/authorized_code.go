package v0

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"net/http"
)

var _ protocol = &authorizedCodeFlow{}

// authorizedCodeFlow implements the grant type as specified by https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3.
type authorizedCodeFlow struct {
	sessions *SessionManager
}

func (a authorizedCodeFlow) Routes(_ core.EchoRouter) {
	// Authorize endpoint is implemented as baseline feature, no need to register it here.
}

func (a authorizedCodeFlow) authzHandlers() []authzHandler {
	return []authzHandler{
		func(m map[string]string, session *Session) (bool, error) {
			return true, nil
		},
	}
}

func (a authorizedCodeFlow) grantHandlers() map[string]grantHandler {
	return map[string]grantHandler{
		"authorization_code": a.validateCode,
	}
}

func (a authorizedCodeFlow) validateCode(params map[string]string) (string, error) {
	code, ok := params["code"]
	if !ok {
		return "", openid4vci.Error{
			Code:        openid4vci.InvalidRequest,
			StatusCode:  http.StatusBadRequest,
			Description: "missing or invalid code parameter",
		}
	}
	session := a.sessions.Get(code)
	if session == nil {
		return "", openid4vci.Error{
			Code:        openid4vci.InvalidRequest,
			StatusCode:  http.StatusBadRequest,
			Description: "invalid code",
		}
	}
	return session.Scope, nil
}
