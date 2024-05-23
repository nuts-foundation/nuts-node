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

package usersession

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

// Middleware is Echo middleware that ensures a user session is available in the request context (unless skipped).
// If no session is available, a new session is created.
// All HTTP requests to which the middleware is applied must contain a tenant parameter in the HTTP request path, specified as ':did'
type Middleware struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper
	// TimeOut is the maximum lifetime of a user session.
	TimeOut time.Duration
	// Store is the session store to use for storing user sessions.
	Store storage.SessionStore
	// CookiePath is a function that returns the path for the user session cookie.
	CookiePath func(tenantDID did.DID) string
}

func (u Middleware) Handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(echoCtx echo.Context) error {
		if u.Skipper(echoCtx) {
			return next(echoCtx)
		}
		tenantDIDRaw := echoCtx.Param("did")
		if tenantDIDRaw == "" {
			// Indicates misconfiguration
			return errors.New("missing tenant DID")
		}
		tenantDID, err := did.ParseDID(tenantDIDRaw)
		if err != nil {
			return fmt.Errorf("invalid tenant DID: %w", err)
		}

		sessionID, sessionData, err := u.loadUserSession(echoCtx, *tenantDID)
		if err != nil {
			// Should only really occur in exceptional circumstances (e.g. cookie survived after intended max age).
			log.Logger().WithError(err).Info("Invalid user session, a new session will be created")
		}
		if sessionData == nil {
			sessionData, err = createUserSession(*tenantDID, u.TimeOut)
			sessionID = crypto.GenerateNonce()
			if err := u.Store.Put(sessionID, sessionData); err != nil {
				return err
			}
			if err != nil {
				return fmt.Errorf("create user session: %w", err)
			}
			// By scoping the cookie to a tenant (DID)-specific path, the user can have a session per tenant DID on the same domain.
			echoCtx.SetCookie(u.createUserSessionCookie(sessionID, u.CookiePath(*tenantDID)))
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
func (u Middleware) loadUserSession(cookies CookieReader, tenantDID did.DID) (string, *Data, error) {
	cookie, err := cookies.Cookie(userSessionCookieName)
	if err != nil {
		// sadly, no cookie for you
		// Cookie only returns http.ErrNoCookie
		return "", nil, nil
	}
	session := new(Data)
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
	if !session.TenantDID.Equals(tenantDID) {
		return "", nil, fmt.Errorf("session belongs to another tenant (%s)", session.TenantDID)
	}
	return sessionID, session, nil
}

func createUserSession(tenantDID did.DID, timeOut time.Duration) (*Data, error) {
	userJWK, userDID, err := generateUserSessionJWK()
	if err != nil {
		return nil, err
	}
	userJWKBytes, err := json.Marshal(userJWK)
	if err != nil {
		return nil, err
	}
	// create user session wallet
	return &Data{
		TenantDID: tenantDID,
		Wallet: UserWallet{
			JWK: userJWKBytes,
			DID: *userDID,
		},
		ExpiresAt: time.Now().Add(timeOut),
	}, nil
}

func (u Middleware) createUserSessionCookie(sessionID string, path string) *http.Cookie {
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

// Get retrieves the user session from the request context.
// If the user session is not found, an error is returned.
func Get(ctx context.Context) (*Data, error) {
	result, ok := ctx.Value(userSessionContextKey).(*Data)
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
