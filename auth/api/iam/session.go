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
	ClientID     string
	Scope        string
	OwnDID       did.DID
	ClientState  string
	RedirectURI  string
	ServerState  map[string]interface{}
	ResponseType string
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
