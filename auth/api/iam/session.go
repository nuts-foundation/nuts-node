package iam

import (
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
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
	OwnDID      did.DID
	ClientState string
	RedirectURI string
}

func AddQueryParams(u url.URL, params map[string]string) url.URL {
	values := u.Query()
	for key, value := range params {
		values.Add(key, value)
	}
	u.RawQuery = values.Encode()
	return u
}

func (s Session) CreateRedirectURI(params map[string]string) string {
	redirectURI, _ := url.Parse(s.RedirectURI)
	r := AddQueryParams(*redirectURI, params)
	return r.String()
}
