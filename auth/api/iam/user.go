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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

	// TODO: Here, support for OpenID Connect can be added in the future
	wallet, err := r.createUserSessionWallet(echoCtx.Request().Context(), *verifier, *accessTokenRequest.Body.PreauthorizedUser)
	if err != nil {
		return fmt.Errorf("create user session wallet: %w", err)
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
		VerifierDID: verifier,
		SessionID:   redirectSession.SessionID,
		RedirectURI: accessTokenRequest.Body.RedirectUri,
		Wallet:      *wallet,
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
		values[oauth.RedirectURIParam] = callbackURL.String()
		values[oauth.ResponseTypeParam] = responseTypeCode
		values[oauth.StateParam] = oauthSession.ClientState
		values[oauth.ScopeParam] = accessTokenRequest.Body.Scope
	}
	redirectURL, err := r.auth.IAMClient().CreateAuthorizationRequest(echoCtx.Request().Context(), redirectSession.OwnDID, *verifier, modifier)
	if err != nil {
		return err
	}
	return echoCtx.Redirect(http.StatusFound, redirectURL.String())
}

func (r Wrapper) userRedirectStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(userRedirectTimeout, userRedirectSessionKey...)
}

func (r Wrapper) oauthClientStateStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthClientStateKey...)
}

func (r Wrapper) oauthCodeStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthCodeKey...)
}

func (r Wrapper) createUserSessionWallet(ctx context.Context, issuerDID did.DID, userDetails UserDetails) (*SessionWallet, error) {
	userJWK, userDID, err := generateUserSessionJWK()
	if err != nil {
		return nil, err
	}
	userJWKBytes, err := json.Marshal(userJWK)
	if err != nil {
		return nil, err
	}
	// create user session wallet
	wallet := SessionWallet{
		JWK: userJWKBytes,
	}
	issuanceDate := time.Now()
	expirationData := issuanceDate.Add(userSessionTimeout)
	template := vc.VerifiableCredential{
		Context:        []ssi.URI{credential.NutsV1ContextURI},
		Type:           []ssi.URI{ssi.MustParseURI("EmployeeCredential")},
		Issuer:         issuerDID.URI(),
		IssuanceDate:   &issuanceDate,
		ExpirationDate: &expirationData,
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
	// Generate a EC key pair and JWK for storage
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	userJWK, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, err
	}

	// Now derive the did:jwk DID
	publicKey := key.Public()
	publicUserJWK, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicUserJWKData, err := json.Marshal(publicUserJWK)
	if err != nil {
		return nil, nil, err
	}
	userDID, err := did.ParseDID("did:jwk:" + base64.RawStdEncoding.EncodeToString(publicUserJWKData))
	if err != nil {
		return nil, nil, err
	}

	return userJWK, userDID, nil
}
