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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"html/template"
	"net/http"
	"net/url"
)

func newAuthorizedCodeFlow(sessions *SessionManager) *authorizedCodeFlow {
	authzTemplate, _ := template.ParseFS(assets, "assets/authz_en.html")
	return &authorizedCodeFlow{
		sessions:      sessions,
		authzTemplate: authzTemplate,
	}
}

// authorizedCodeFlow implements the grant type as specified by https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3.
type authorizedCodeFlow struct {
	sessions      *SessionManager
	authzTemplate *template.Template
}

func (a authorizedCodeFlow) Routes(router core.EchoRouter) {
	router.Add(http.MethodPost, "/public/oauth2/:did/authz_consent", a.handleAuthConsent)
}

func (a authorizedCodeFlow) handleAuthzRequest(params map[string]string, session *Session) (*authzResponse, error) {
	// This authz request handling is just for demonstration purposes.
	sessionId := a.sessions.Create(*session)

	// Render HTML
	buf := new(bytes.Buffer)
	// TODO: Support multiple languages
	err := a.authzTemplate.Execute(buf, struct {
		SessionID string
		Session
	}{
		SessionID: sessionId,
		Session:   *session,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to render authorization page: %w", err)
	}
	return &authzResponse{
		html: buf.Bytes(),
	}, nil
}

// handleAuthConsent handles the authorization consent form submission.
func (a authorizedCodeFlow) handleAuthConsent(c echo.Context) error {
	var session *Session
	if sessionID := c.Param("sessionID"); sessionID != "" {
		session = a.sessions.Get(sessionID)
	}
	if session == nil {
		return errors.New("invalid session")
	}

	redirectURI, _ := url.Parse(session.RedirectURI) // Validated on session creation, can't fail
	query := redirectURI.Query()
	query.Add("code", generateCode())
	redirectURI.RawQuery = query.Encode()

	return c.Redirect(http.StatusFound, redirectURI.String())
}

func (a authorizedCodeFlow) validateCode(params map[string]string) (string, error) {
	code, ok := params["code"]
	invalidCodeError := OAuth2Error{
		Code:        InvalidRequest,
		Description: "missing or invalid code parameter",
	}
	if !ok {
		return "", invalidCodeError
	}
	session := a.sessions.Get(code)
	if session == nil {
		return "", invalidCodeError
	}
	return session.Scope, nil
}

func generateCode() string {
	buf := make([]byte, 128/8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}
