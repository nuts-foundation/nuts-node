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
	"fmt"
	"github.com/nuts-foundation/nuts-node/http/user"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

const (
	// oAuthFlowTimeout is the timeout for the oauth flow.
	// The maximum time between the initial authorize request and the final token request.
	oAuthFlowTimeout = time.Minute
	// userRedirectTimeout is the timeout for the user redirect session.
	// This is the maximum time between the creation of the redirect for the user and the actual GET request to the user/wallet page.
	userRedirectTimeout = time.Second * 5
)

var oauthClientStateKey = []string{"oauth", "client_state"}
var oauthCodeKey = []string{"oauth", "code"}
var userRedirectSessionKey = []string{"user", "redirect"}

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
	redirectSession := RedirectSession{}
	err := r.userRedirectStore().GetAndDelete(token, &redirectSession)
	if err != nil {
		log.Logger().Debug("token not found in store")
		return echoCtx.NoContent(http.StatusForbidden)
	}
	accessTokenRequest := redirectSession.AccessTokenRequest

	verifier, err := did.ParseDID(accessTokenRequest.Body.Verifier)
	if err != nil {
		return err
	}

	// Make sure there's a user session, loaded with EmployeeCredential
	userSession, err := user.GetSession(echoCtx.Request().Context())
	if err != nil {
		return err
	}
	if err := r.provisionUserSession(echoCtx.Request().Context(), userSession, *redirectSession.AccessTokenRequest.Body.PreauthorizedUser); err != nil {
		return fmt.Errorf("couldn't provision user session: %w", err)
	}

	// use DPoP or not
	useDPoP := true
	if redirectSession.AccessTokenRequest.Body.TokenType != nil && strings.ToLower(string(*redirectSession.AccessTokenRequest.Body.TokenType)) == strings.ToLower(AccessTokenTypeBearer) {
		useDPoP = false
	}

	// get AS metadata
	oauthIssuer, err := didweb.DIDToURL(*verifier)
	if err != nil {
		return err
	}
	metadata, err := r.auth.IAMClient().AuthorizationServerMetadata(echoCtx.Request().Context(), oauthIssuer.String())
	if err != nil {
		return fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.AuthorizationEndpoint) == 0 {
		return fmt.Errorf("no authorization_endpoint found for %s", verifier.String())
	}
	if len(metadata.TokenEndpoint) == 0 {
		return fmt.Errorf("no token_endpoint found for %s", verifier.String())
	}
	// create oauthSession with userID from request
	// generate new sessionID and clientState with crypto.GenerateNonce()
	oauthSession := OAuthSession{
		ClientState:   crypto.GenerateNonce(),
		OwnDID:        &redirectSession.OwnDID,
		PKCEParams:    generatePKCEParams(),
		RedirectURI:   accessTokenRequest.Body.RedirectUri,
		SessionID:     redirectSession.SessionID,
		UseDPoP:       useDPoP,
		VerifierDID:   verifier,
		TokenEndpoint: metadata.TokenEndpoint,
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
	modifier := func(values map[string]string) {
		values[oauth.CodeChallengeParam] = oauthSession.PKCEParams.Challenge
		values[oauth.CodeChallengeMethodParam] = oauthSession.PKCEParams.ChallengeMethod
		values[oauth.RedirectURIParam] = callbackURL.String()
		values[oauth.ResponseTypeParam] = oauth.CodeResponseType
		values[oauth.StateParam] = oauthSession.ClientState
		values[oauth.ScopeParam] = accessTokenRequest.Body.Scope
	}
	redirectURL, err := r.createAuthorizationRequest(echoCtx.Request().Context(), redirectSession.OwnDID, verifier, modifier)
	if err != nil {
		return err
	}
	return echoCtx.Redirect(http.StatusFound, redirectURL.String())
}

// userRedirectStore is used to store a short-lived RedirectSession that persist state between the RequestUserAccessToken
// call and the redirect back to this node to initiate the actual authorization request. Burn on use.
func (r Wrapper) userRedirectStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(userRedirectTimeout, userRedirectSessionKey...)
}

// oauthClientStateStore is used tot store the client's OAuthSession
func (r Wrapper) oauthClientStateStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...)
}

func (r Wrapper) provisionUserSession(ctx context.Context, session *user.Session, preAuthorizedUser UserDetails) error {
	if len(session.Wallet.Credentials) > 0 {
		// already provisioned
		return nil
	}
	employeeCredential, err := r.issueEmployeeCredential(ctx, *session, preAuthorizedUser)
	if err != nil {
		return err
	}
	session.Wallet.Credentials = append(session.Wallet.Credentials, *employeeCredential)
	return session.Save()
}

func (r Wrapper) issueEmployeeCredential(ctx context.Context, session user.Session, userDetails UserDetails) (*vc.VerifiableCredential, error) {
	issuanceDate := time.Now()
	expirationDate := session.ExpiresAt
	template := vc.VerifiableCredential{
		Context:        []ssi.URI{credential.NutsV1ContextURI},
		Type:           []ssi.URI{ssi.MustParseURI("EmployeeCredential")},
		Issuer:         session.TenantDID.URI(),
		IssuanceDate:   issuanceDate,
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{
			map[string]string{
				"id":         session.Wallet.DID.String(),
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
	return employeeCredential, nil
}
