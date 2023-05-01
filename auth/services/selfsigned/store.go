package selfsigned

import (
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"sync"
)

type memorySessionStore struct {
	sessions map[string]types.Session
	lock     sync.Mutex
}

func NewMemorySessionStore() types.SessionStore {
	return &memorySessionStore{sessions: make(map[string]types.Session)}
}

func (s *memorySessionStore) Store(sessionID string, session types.Session) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[sessionID] = session
}

func (s *memorySessionStore) Load(sessionID string) (types.Session, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	session, ok := s.sessions[sessionID]
	return session, ok
}

func (s *memorySessionStore) CheckAndSetStatus(sessionID string, expectedStatus, status string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	if session.Status != expectedStatus {
		return false
	}
	session.Status = status
	s.sessions[sessionID] = session
	return true
}

func (s *memorySessionStore) Delete(sessionID string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.sessions, sessionID)
}
