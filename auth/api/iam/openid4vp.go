package iam

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"html/template"
	"net/http"
)

// openID4VP implements verifiable presentation exchanges as specified by https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
type openID4VP struct {
	sessions      *SessionManager
	authzTemplate *template.Template
}

func (a openID4VP) Routes(router core.EchoRouter) {
	router.Add(http.MethodPost, "/public/oauth2/:did/authz_consent", a.handleAuthConsent)
}

func (a openID4VP) handleAuthzRequest(params map[string]string, session *Session) (*authzResponse, error) {
	presentationDef := params["presentation_definition"]
	presentationDefUri := params["presentation_definition_uri"]
	clientIdScheme := params["client_id_scheme"]
	clientMetadata := params["client_metadata"]
	clientMetadataUri := params["client_metadata_uri"]

	if presentationDef == "" &&
		presentationDefUri == "" &&
		clientIdScheme == "" &&
		clientMetadata == "" &&
		clientMetadataUri == "" {
		// Not an OpenID4VP Authorization Request
		return nil, nil
	}
	sessionId := a.sessions.Create(*session)

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2357
	// TODO: Retrieve presentation definition
	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2359
	// TODO: Match presentation definition, show credential in HTML page

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
func (a openID4VP) handleAuthConsent(c echo.Context) error {
	// TODO: Needs authentication?
	var session *Session
	if sessionID := c.Param("sessionID"); sessionID != "" {
		session = a.sessions.Get(sessionID)
	}
	if session == nil {
		return errors.New("invalid session")
	}
	// TODO: create presentation submission
	// TODO: check response mode, and submit accordingly (direct_post)
	return c.Redirect(http.StatusFound, session.CreateRedirectURI(map[string]string{}))
}
