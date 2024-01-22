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
	"context"
	"github.com/nuts-foundation/nuts-node/storage"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/crypto"
	http2 "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

const (
	// oAuthFlowTimeout is the timeout for the oauth flow.
	// The maximum time between the initial authorize request and the final token request.
	oAuthFlowTimeout = time.Minute
	// userRedirectTimeout is the timeout for the user redirect session.
	// This is the maximum time between the creation of the redirect for the user and the actual GET request to the user/wallet page.
	userRedirectTimeout = time.Second * 5
	// userSessionTimeout is the timeout for the user session.
	// This is the TTL of the server side state and the cookie.
	userSessionTimeout = time.Hour
)

var oauthClientStateKey = []string{"oauth", "client_state"}
var oauthCodeKey = []string{"oauth", "code"}
var userRedirectSessionKey = []string{"user", "redirect"}
var userSessionKey = []string{"user", "session"}

func (r Wrapper) requestUserAccessToken(_ context.Context, requester did.DID, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	// generate a redirect token valid for 5 seconds
	token := crypto.GenerateNonce()
	store := r.userRedirectStore()
	// put the request in the store
	err := store.Put(token, RedirectSession{
		OwnDID:             requester,
		AccessTokenRequest: request,
	})
	if err != nil {
		return nil, err
	}
	// generate a link to the redirect endpoint
	webURL, err := didweb.DIDToURL(requester)
	if err != nil {
		return nil, err
	}
	// redirect to generic user page, context of token will render correct page
	redirectURL := http2.AddQueryParams(*webURL.JoinPath("user"), map[string]string{
		"token": token,
	})
	return RequestAccessToken302Response{
		Headers: RequestAccessToken302ResponseHeaders{
			Location: redirectURL.String(),
		},
	}, nil
}

// handleUserLanding is the handler for the landing page of the user.
// It renders the page with the correct context based on the token.
func (r Wrapper) handleUserLanding(echoCtx echo.Context) error {
	// todo: user authentication is currently not implemented, user consent is not implemented
	// This means that this handler succeeds if the token is valid
	// It only checks for an existing RequestAccessTokenRequestObject in the store
	// It does not (yet) check for user consent or the existence of a user wallet
	// If present it will return a redirect to the remote authorization server

	// extract token from query parameters
	token := echoCtx.QueryParam("token")
	if token == "" {
		log.Logger().Debug("missing token")
		return echoCtx.NoContent(http.StatusForbidden)
	}

	// extract request from store
	store := r.userRedirectStore()
	redirectSession := RedirectSession{}
	err := store.Get(token, &redirectSession)
	if err != nil {
		log.Logger().Debug("token not found in store")
		return echoCtx.NoContent(http.StatusForbidden)
	}
	accessTokenRequest := redirectSession.AccessTokenRequest
	// burn token
	err = store.Delete(token)
	if err != nil {
		//rare, log just in case
		log.Logger().WithError(err).Warn("delete token failed")
	}
	// create UserSession with userID from request
	// generate new sessionID and clientState with crypto.GenerateNonce()
	userSession := UserSession{
		ClientState: crypto.GenerateNonce(),
		SessionID:   crypto.GenerateNonce(),
		UserID:      *accessTokenRequest.Body.UserID, // should be there...
		OwnDID:      redirectSession.OwnDID,
	}

	// store user session in session store under sessionID and clientState
	err = r.userSessionStore().Put(userSession.SessionID, userSession)
	if err != nil {
		return err
	}
	err = r.oauthClientStateStore().Put(userSession.ClientState, userSession)
	if err != nil {
		return err
	}
	verifier, err := did.ParseDID(accessTokenRequest.Body.Verifier)
	if err != nil {
		return err
	}
	redirectURL, err := r.auth.RelyingParty().CreateAuthorizationRequest(echoCtx.Request().Context(), redirectSession.OwnDID, *verifier, accessTokenRequest.Body.Scope, userSession.ClientState)
	if err != nil {
		return err
	}
	return echoCtx.Redirect(http.StatusFound, redirectURL.String())
}

func (r Wrapper) userRedirectStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(userRedirectTimeout, userRedirectSessionKey...)
}

func (r Wrapper) userSessionStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(userSessionTimeout, userSessionKey...)
}

func (r Wrapper) oauthClientStateStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...)
}

func (r Wrapper) oauthCodeStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthCodeKey...)
}
