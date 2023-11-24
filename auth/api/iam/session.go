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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/http"
	"net/url"
)

// OAuthSession is the session object for an OAuth2.0 flow (request/authorize/token).
type OAuthSession struct {
	ClientID     string
	Scope        string
	OwnDID       did.DID
	ClientState  string
	RedirectURI  string
	ServerState  map[string]interface{}
	ResponseType string
}

// UserSession is the session object for handling the user browser session.
// A RedirectSession is replaced with a UserSession.
type UserSession struct {
	ClientState string
	SessionID   string
	UserID      string
	OwnDID      did.DID
}

// RedirectSession is the session object that is used to redirect the user to a Nuts node website.
// It stores information from the internal API call that started the request access token.
// The key to this session is passed to the user via a 302 redirect.
type RedirectSession struct {
	OwnDID             did.DID
	AccessTokenRequest RequestAccessTokenRequestObject
}

func (s OAuthSession) CreateRedirectURI(params map[string]string) string {
	redirectURI, _ := url.Parse(s.RedirectURI)
	r := http.AddQueryParams(*redirectURI, params)
	return r.String()
}
