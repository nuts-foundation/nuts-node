/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package selfsigned

import (
	"context"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"sync"
	"time"
)

type memorySessionStore struct {
	sessions       map[string]*types.Session
	lock           sync.Mutex
	expiryInterval time.Duration
}

func NewMemorySessionStore() types.SessionStore {
	return &memorySessionStore{
		sessions:       make(map[string]*types.Session),
		expiryInterval: time.Second,
	}
}

func (s *memorySessionStore) Store(sessionID string, session types.Session) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[sessionID] = &session
}

func (s *memorySessionStore) Load(sessionID string) (types.Session, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if session, ok := s.sessions[sessionID]; ok {
		return *session, true
	}

	return types.Session{}, false
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

func (s *memorySessionStore) Start(ctx context.Context) {
	done := ctx.Done()

	go func() {
		timer := time.NewTicker(s.expiryInterval)
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				s.evict()
			}
		}
	}()
}

func (s *memorySessionStore) evict() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for k, v := range s.sessions {
		if v.ExpiresAt.Before(time.Now().Add(-10 * time.Minute)) {
			delete(s.sessions, k)
		}
	}
}
