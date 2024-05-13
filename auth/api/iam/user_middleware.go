package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"net/http"
	"time"
)

type UserAuthMiddleware struct {
	Skipper           echoMiddleware.Skipper
	userRedirectStore storage.SessionStore
	userSessionStore  storage.SessionStore
	auth              auth.AuthenticationServices
	tenantParamName   string
}

func (u UserAuthMiddleware) Handle(fn echo.HandlerFunc) echo.HandlerFunc {
	return func(echoCtx echo.Context) error {
		if u.Skipper != nil && u.Skipper(echoCtx) {
			return fn(echoCtx)
		}
		u.loadOrCreateSession(echoCtx)
		return fn(echoCtx)
	}
}

func (u UserAuthMiddleware) loadOrCreateSession(echoCtx echo.Context) error {
	preAuthorizedUser := u.getPreAuthorizedUser(echoCtx)
	tenantDID, err := did.ParseDID(echoCtx.Param(u.tenantParamName))
	if err != nil {
		return fmt.Errorf("unable to parse tenant DID: %w", err)
	}

	session, err := u.loadUserSession(echoCtx, *tenantDID, preAuthorizedUser)
	if err != nil {
		// Should only really occur in exceptional circumstances (e.g. cookie survived after intended max age).
		log.Logger().WithError(err).Info("Invalid user session, a new session will be created")
	}
	// TODO: Can we use the tenantDID as is, or do we need to validate it? In the original user session code,
	//       it was taken from the redirect session
	if session == nil {

	}

}

func (u UserAuthMiddleware) createNewSession(echoCtx echo.Context, tenantDID did.DID, preAuthorizedUser *UserDetails) error {
	wallet, err := u.createUserWallet(echoCtx.Request().Context(), tenantDID, *preAuthorizedUser)
	if err != nil {
		return fmt.Errorf("create user wallet: %w", err)
	}
	// this causes the session cookie to be set
	if err = u.createUserSession(echoCtx, UserSession{
		TenantDID: tenantDID,
		Wallet:    *wallet,
	}); err != nil {
		return fmt.Errorf("create user session: %w", err)
	}
}

func (u UserAuthMiddleware) getPreAuthorizedUser(ctx echo.Context) *UserDetails {
	token := ctx.QueryParam("token")
	if token == "" {
		return nil
	}
	redirectSession := RedirectSession{}
	err := u.userRedirectStore.Get(token, &redirectSession)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			log.Logger().Warnf("Failed to load redirect session for creating user session: %v", err)
		}
		return nil
	}
	return redirectSession.AccessTokenRequest.Body.PreauthorizedUser
}

// loadUserSession loads the user session given the session ID in the cookie.
// If there is no session cookie (not yet authenticated, or the session expired), nil is returned.
// If another, technical error occurs when retrieving the session.
func (u UserAuthMiddleware) loadUserSession(cookies CookieReader, tenantDID did.DID, preAuthorizedUser *UserDetails) (*UserSession, error) {
	cookie, err := cookies.Cookie(userSessionCookieName)
	if err != nil {
		// sadly, no cookie for you
		// Cookie only returns http.ErrNoCookie
		return nil, nil
	}
	session := new(UserSession)
	if err = u.userSessionStore.Get(cookie.Value, session); errors.Is(err, storage.ErrNotFound) {
		return nil, errors.New("unknown or expired session")
	} else if err != nil {
		// other error occurred
		return nil, fmt.Errorf("invalid user session: %w", err)
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

func (u UserAuthMiddleware) createUserSession(ctx echo.Context, session UserSession) error {
	sessionID := crypto.GenerateNonce()
	if err := u.userSessionStore.Put(sessionID, session); err != nil {
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
	if u.auth.PublicURL().Path != "" {
		path = u.auth.PublicURL().Path
	} else {
		path = "/"
	}
	ctx.SetCookie(createUserSessionCookie(sessionID, path))
	return nil
}

func createUserSessionCookie(sessionID string, path string) *http.Cookie {
	return &http.Cookie{
		Name:     userSessionCookieName,
		Value:    sessionID,
		Path:     path,
		MaxAge:   int(userSessionTimeout.Seconds()),
		Secure:   true,
		HttpOnly: true,                    // do not let JavaScript
		SameSite: http.SameSiteStrictMode, // do not allow the cookie to be sent with cross-site requests
	}
}

func (u UserAuthMiddleware) createUserWallet(ctx context.Context, issuerDID did.DID, userDetails UserDetails) (*UserWallet, error) {
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
	employeeCredential, err := u.vcr.Issuer().Issue(ctx, template, issuer.CredentialOptions{
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
