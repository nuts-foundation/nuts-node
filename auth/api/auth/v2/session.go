package v2

import (
	"github.com/google/uuid"
	"net/url"
	"sync"
)

type SessionManager struct {
	sessions *sync.Map
}

func (s *SessionManager) Create(session Session) string {
	// TODO: Session expiration
	// TODO: Session storage
	// TODO: Session pinning and other safety measures (see OAuth2 Threat Model)
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

func (s Session) CreateRedirectURI(params map[string]string) string {
	redirectURI, _ := url.Parse(s.RedirectURI)
	query := redirectURI.Query()
	for key, value := range params {
		query.Add(key, value)
	}
	redirectURI.RawQuery = query.Encode()
	return redirectURI.String()
}
