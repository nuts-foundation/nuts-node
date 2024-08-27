/*
 * Copyright (C) 2024 Nuts community
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

package user

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"net/http"
	"time"
)

var userSessionContextKey = struct{}{}

// userSessionCookieName is the name of the cookie used to store the user session.
// It uses the __Secure prefix, that instructs the user agent to treat it as a secure cookie:
// - Must be set with the Secure attribute
// - Must be set from an HTTPS uri
// Note that earlier, we used the Host cookie prefix, but that doesn't work in a multi-tenant environment,
// since then the Path attribute (used for multi-tenancy) can't be used.
// Also see:
// - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
// - https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
const userSessionCookieName = "__Secure-SID"

// SessionMiddleware is Echo middleware that ensures a user session is available in the request context (unless skipped).
// If no session is available, a new session is created.
// All HTTP requests to which the middleware is applied must contain a tenant parameter in the HTTP request path, specified as ':did'
type SessionMiddleware struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper
	// TimeOut is the maximum lifetime of a user session.
	TimeOut time.Duration
	// Store is the session store to use for storing user sessions.
	Store storage.SessionStore
	// CookiePath is a function that returns the path for the user session cookie.
	CookiePath func(subjectID string) string
}

func (u SessionMiddleware) Handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(echoCtx echo.Context) error {
		if u.Skipper(echoCtx) {
			return next(echoCtx)
		}
		subjectID := echoCtx.Param("subjectID")
		if subjectID == "" {
			// Indicates misconfiguration
			return errors.New("missing subject ID")
		}

		sessionID, sessionData, err := u.loadUserSession(echoCtx, subjectID)
		if err != nil {
			// Should only really occur in exceptional circumstances (e.g. cookie survived after intended max age).
			log.Logger().WithError(err).Info("Invalid user session, a new session will be created")
		}
		if sessionData == nil {
			sessionData, err = createUserSession(subjectID, u.TimeOut)
			sessionID = crypto.GenerateNonce()
			if err := u.Store.Put(sessionID, sessionData); err != nil {
				return err
			}
			if err != nil {
				return fmt.Errorf("create user session: %w", err)
			}
			// By scoping the cookie to a tenant (DID)-specific path, the user can have a session per tenant DID on the same domain.
			echoCtx.SetCookie(u.createUserSessionCookie(sessionID, u.CookiePath(subjectID)))
		}
		sessionData.Save = func() error {
			return u.Store.Put(sessionID, sessionData)
		}
		// Session data is put in request context for access by API handlers
		echoCtx.SetRequest(echoCtx.Request().WithContext(context.WithValue(echoCtx.Request().Context(), userSessionContextKey, sessionData)))

		return next(echoCtx)
	}
}

// loadUserSession loads the user session given the session ID in the cookie.
// If there is no session cookie (not yet authenticated, or the session expired), nil is returned.
// If another, technical error occurs when retrieving the session.
func (u SessionMiddleware) loadUserSession(cookies CookieReader, subjectID string) (string, *Session, error) {
	cookie, err := cookies.Cookie(userSessionCookieName)
	if err != nil {
		// sadly, no cookie for you
		// Cookie only returns http.ErrNoCookie
		return "", nil, nil
	}
	session := new(Session)
	sessionID := cookie.Value
	if err = u.Store.Get(sessionID, session); errors.Is(err, storage.ErrNotFound) {
		return "", nil, errors.New("unknown or expired session")
	} else if err != nil {
		// other error occurred
		return "", nil, fmt.Errorf("invalid user session: %w", err)
	}
	if session.ExpiresAt.Before(time.Now()) {
		// session has expired: possible if session was updated, which causes the TTL to be updated.
		// Could also be implemented by separating "create" and "update" in the session store,
		// but this adds less complexity.
		return "", nil, errors.New("expired session")
	}
	if session.SubjectID != subjectID {
		return "", nil, fmt.Errorf("session belongs to another subject (%s)", session.SubjectID)
	}
	return sessionID, session, nil
}

func createUserSession(subjectID string, timeOut time.Duration) (*Session, error) {
	userJWK, userDID, err := generateUserSessionJWK()
	if err != nil {
		return nil, err
	}
	userJWKBytes, err := json.Marshal(userJWK)
	if err != nil {
		return nil, err
	}
	// create user session wallet
	return &Session{
		SubjectID: subjectID,
		Wallet: Wallet{
			JWK: userJWKBytes,
			DID: *userDID,
		},
		ExpiresAt: time.Now().Add(timeOut),
	}, nil
}

func (u SessionMiddleware) createUserSessionCookie(sessionID string, path string) *http.Cookie {
	// Do not set Expires: then it isn't a session cookie anymore.
	return &http.Cookie{
		Name:     userSessionCookieName,
		Value:    sessionID,
		Path:     path,
		MaxAge:   int(u.TimeOut.Seconds()),
		Secure:   true,                    // only transfer over HTTPS
		HttpOnly: true,                    // do not let JavaScript interact with the cookie
		SameSite: http.SameSiteStrictMode, // do not allow the cookie to be sent with cross-site requests
	}
}

// GetSession retrieves the user session from the request context.
// If the user session is not found, an error is returned.
func GetSession(ctx context.Context) (*Session, error) {
	result, ok := ctx.Value(userSessionContextKey).(*Session)
	if !ok {
		return nil, errors.New("no user session found")
	}
	return result, nil
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

// Session is a session-bound Verifiable Credential wallet.
type Session struct {
	// Save is a function that persists the session.
	Save func() error `json:"-"`
	// SubjectID identifies the requesting subject when the user session was created.
	// A session needs to be scoped to the subject, since the session gives access to the subject's wallets,
	// and the user session might contain session-bound credentials (e.g. EmployeeCredential) that were issued by the subject.
	SubjectID string    `json:"subjectID"`
	Wallet    Wallet    `json:"wallet"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Wallet is a session-bound Verifiable Credential wallet.
// It's an in-memory wallet which contains the user's private key in plain text.
// This is OK, since the associated credentials are intended for protocol compatibility (OpenID4VP with a low-assurance EmployeeCredential),
// when an actual user wallet is involved, this wallet isn't used.
type Wallet struct {
	Credentials []vc.VerifiableCredential
	// JWK is an in-memory key pair associated with the user's wallet in JWK form.
	JWK []byte
	// DID is the did:jwk DID of the user's wallet.
	DID did.DID
}

// Key returns the JWK as jwk.Key
func (w Wallet) Key() (jwk.Key, error) {
	set, err := jwk.Parse(w.JWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	result, available := set.Key(0)
	if !available {
		return nil, errors.New("expected exactly 1 key in the JWK set")
	}
	return result, nil
}

// CookieReader is an interface for reading cookies from an HTTP request.
// It is implemented by echo.Context and http.Request.
type CookieReader interface {
	// Cookie returns the named cookie provided in the request.
	Cookie(name string) (*http.Cookie, error)
}
