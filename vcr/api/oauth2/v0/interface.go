package v0

import (
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/core"
	"sync"
)

type protocol interface {
	core.Routable
	authzHandlers() []authzHandler
	grantHandlers() map[string]grantHandler
}

// authzHandler defines a function for checking authorization requests given the input parameters, used to initiate the authorization code flow.
type authzHandler func(map[string]string, *Session) (bool, error)

// grantHandler defines a function for checking a grant given the input parameters, used to validate token requests.
// It returns the requested scopes if the validation succeeds.
type grantHandler func(map[string]string) (string, error)

type SessionManager struct {
	sessions *sync.Map
}

func (s *SessionManager) Create(session Session) string {
	id := uuid.NewString()
	s.sessions.Store(id, session)
	return id
}

func (s *SessionManager) Get(id string) *Session {
	session, ok := s.sessions.Load(id)
	if !ok {
		return nil
	}
	result := session.(Session)
	return &result
}

type Session struct {
	ClientID    string
	Scope       string
	ClientState string
	RedirectURI string
}
