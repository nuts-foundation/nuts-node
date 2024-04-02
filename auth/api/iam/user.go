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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	issuer "github.com/nuts-foundation/nuts-node/vcr/issuer"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/crypto"
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
var oauthServerStateKey = []string{"oauth", "server_state"}
var userRedirectSessionKey = []string{"user", "redirect"}
var userSessionKey = []string{"user", "session"}

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

	verifier, err := did.ParseDID(accessTokenRequest.Body.Verifier)
	if err != nil {
		return err
	}

	session, err := r.loadUserSession(echoCtx, redirectSession.OwnDID, accessTokenRequest.Body.PreauthorizedUser)
	if err != nil {
		// Should only really occur in exceptional circumstances (e.g. cookie survived after intended max age).
		log.Logger().WithError(err).Info("Invalid user session, a new session will be created")
	}
	if session == nil {
		wallet, err := r.createUserWallet(echoCtx.Request().Context(), redirectSession.OwnDID, *accessTokenRequest.Body.PreauthorizedUser)
		if err != nil {
			return fmt.Errorf("create user wallet: %w", err)
		}
		// this causes the session cookie to be set
		if err = r.createUserSession(echoCtx, UserSession{
			TenantDID: redirectSession.OwnDID,
			Wallet:    *wallet,
		}); err != nil {
			return fmt.Errorf("create user session: %w", err)
		}
	}

	// burn token
	err = store.Delete(token)
	if err != nil {
		//rare, log just in case
		log.Logger().WithError(err).Warn("delete token failed")
	}
	// create oauthSession with userID from request
	// generate new sessionID and clientState with crypto.GenerateNonce()
	oauthSession := OAuthSession{
		ClientState: crypto.GenerateNonce(),
		OwnDID:      &redirectSession.OwnDID,
		PKCEParams:  generatePKCEParams(),
		RedirectURI: accessTokenRequest.Body.RedirectUri,
		SessionID:   redirectSession.SessionID,
		VerifierDID: verifier,
	}
	// store user session in session store under sessionID and clientState
	err = r.oauthClientStateStore().Put(oauthSession.ClientState, oauthSession)
	if err != nil {
		return err
	}

	// construct callback URL to be used in (Signed)AuthorizationRequest
	callbackURL, err := createOAuth2BaseURL(redirectSession.OwnDID)
	if err != nil {
		return fmt.Errorf("failed to create callback URL: %w", err)
	}
	callbackURL = callbackURL.JoinPath(oauth.CallbackPath)
	modifier := func(values map[string]interface{}) {
		values[oauth.CodeChallengeParam] = oauthSession.PKCEParams.Challenge
		values[oauth.CodeChallengeMethodParam] = oauthSession.PKCEParams.ChallengeMethod
		values[oauth.RedirectURIParam] = callbackURL.String()
		values[oauth.ResponseTypeParam] = responseTypeCode
		values[oauth.StateParam] = oauthSession.ClientState
		values[oauth.ScopeParam] = accessTokenRequest.Body.Scope
	}
	// TODO: First create user session, or AuthorizationRequest first? (which one is more expensive? both sign stuff)
	redirectURL, err := r.auth.IAMClient().CreateAuthorizationRequest(echoCtx.Request().Context(), redirectSession.OwnDID, *verifier, modifier)
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

// loadUserSession loads the user session given the session ID in the cookie.
// If there is no session cookie (not yet authenticated, or the session expired), nil is returned.
// If another, technical error occurs when retrieving the session.
func (r Wrapper) loadUserSession(cookies CookieReader, tenantDID did.DID, preAuthorizedUser *UserDetails) (*UserSession, error) {
	cookie, err := cookies.Cookie(userSessionCookieName)
	if err != nil {
		// sadly, no cookie for you
		// Cookie only returns http.ErrNoCookie
		return nil, nil
	}
	session := new(UserSession)
	if err = r.userSessionStore().Get(cookie.Value, session); errors.Is(err, storage.ErrNotFound) {
		return nil, errors.New("unknown or expired session")
	} else if err != nil {
		// other error occurred
		return nil, err
	}
	// Note that the session itself does not have an expiration field:
	// it depends on the session store to clean up when it expires.
	if !session.TenantDID.Equals(tenantDID) {
		return nil, fmt.Errorf("session belongs to another tenant (%s)", session.TenantDID)
	}
	// If the existing session was created for a pre-authorized user, the call to RequestUserAccessToken() must be
	// for the same user.
	// TODO: When we support external Identity Providers, make sure the existing session was not for a preauthorized user.
	if preAuthorizedUser != nil && *preAuthorizedUser != *session.PreAuthorizedUser {
		return nil, errors.New("session belongs to another pre-authorized user")
	}
	return session, nil
}

func (r Wrapper) createUserSession(ctx echo.Context, session UserSession) error {
	sessionID := crypto.GenerateNonce()
	if err := r.userSessionStore().Put(sessionID, session); err != nil {
		return err
	}
	// Do not set Expires: then it isn't a session cookie anymore.
	// TODO: we could make this more secure by narrowing the Path, but we currently have the following user-facing paths:
	// 		 - /iam/:did/(openid4vp_authz_accept)
	// 		 - /oauth2/:did/user
	// 		 If we move these under a common base path (/oauth2 or /iam), we could use that as Path property
	// 		 The issue with the current approach is that we have a single cookie for the whole domain,
	// 		 thus a new user session for a different DID will overwrite the current one (since a new cookie is created).
	//       By scoping the cookies to a tenant (DID)-specific path, they can co-exist.
	var path string
	if r.auth.PublicURL().Path != "" {
		path = r.auth.PublicURL().Path
	} else {
		path = "/"
	}
	ctx.SetCookie(&http.Cookie{
		Name:     userSessionCookieName,
		Value:    sessionID,
		Path:     path,
		MaxAge:   int(userSessionTimeout.Seconds()),
		Secure:   true,
		HttpOnly: true,                    // do not let JavaScript
		SameSite: http.SameSiteStrictMode, // do not allow the cookie to be sent with cross-site requests
	})
	return nil
}

func (r Wrapper) createUserWallet(ctx context.Context, issuerDID did.DID, userDetails UserDetails) (*UserWallet, error) {
	userJWK, userDID, err := generateUserSessionJWK()
	if err != nil {
		return nil, err
	}
	userJWKBytes, err := json.Marshal(userJWK)
	if err != nil {
		return nil, err
	}
	// create user session wallet
	wallet := UserWallet{
		JWK: userJWKBytes,
		DID: *userDID,
	}
	issuanceDate := time.Now()
	expirationDate := issuanceDate.Add(userSessionTimeout)
	template := vc.VerifiableCredential{
		Context:        []ssi.URI{credential.NutsV1ContextURI},
		Type:           []ssi.URI{ssi.MustParseURI("EmployeeCredential")},
		Issuer:         issuerDID.URI(),
		IssuanceDate:   issuanceDate,
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{
			map[string]string{
				"id":         userDID.String(),
				"identifier": userDetails.Id,
				"name":       userDetails.Name,
				"roleName":   userDetails.Role,
			},
		},
	}
	employeeCredential, err := r.vcr.Issuer().Issue(ctx, template, issuer.CredentialOptions{
		Format:                   vc.JWTCredentialProofFormat,
		Publish:                  false,
		Public:                   false,
		WithStatusListRevocation: false,
	})
	if err != nil {
		return nil, fmt.Errorf("issue EmployeeCredential: %w", err)
	}
	wallet.Credentials = append(wallet.Credentials, *employeeCredential)
	return &wallet, nil
}

func generateUserSessionJWK() (jwk.Key, *did.DID, error) {
	// Generate a key pair and JWK for storage
	userJWK, err := crypto.GenerateJWK()
	if err != nil {
		return nil, nil, err
	}
	// Now derive the did:jwk DID
	publicKey, err := userJWK.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	publicUserJSON, err := json.Marshal(publicKey)
	if err != nil {
		return nil, nil, err
	}
	userDID, err := did.ParseDID("did:jwk:" + base64.RawStdEncoding.EncodeToString(publicUserJSON))
	if err != nil {
		return nil, nil, err
	}
	if err := userJWK.Set(jwk.KeyIDKey, userDID.String()+"#0"); err != nil {
		return nil, nil, err
	}

	return userJWK, userDID, nil
}
