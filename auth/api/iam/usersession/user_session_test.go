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
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var tenantDID = did.MustParseDID("did:web:example.com:iam:123")
var userDID = did.MustParseDID("did:jwk:really-a-jwk")

var sessionCookie = http.Cookie{
	Name:     "__Secure-SID",
	Value:    "sessionID",
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteStrictMode,
}

type testCookieReader http.Cookie

func (t *testCookieReader) Cookie(name string) (*http.Cookie, error) {
	if t != nil && name == t.Name {
		return (*http.Cookie)(t), nil
	}
	return nil, http.ErrNoCookie
}

func TestMiddleware_Handle(t *testing.T) {
	t.Run("ok - session is created", func(t *testing.T) {
		instance, sessionStore := createInstance(t)
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/"+tenantDID.String(), nil), httpResponse)
		echoContext.SetParamNames("did")
		echoContext.SetParamValues(tenantDID.String())

		var capturedSession *Data
		err := instance.Handle(func(c echo.Context) error {
			var err error
			capturedSession, err = Get(c.Request().Context())
			return err
		})(echoContext)

		assert.NoError(t, err)
		assert.NotNil(t, capturedSession)
		assert.Equal(t, tenantDID, capturedSession.TenantDID)
		// Assert stored session
		var storedSession = new(Data)
		cookie := httpResponse.Result().Cookies()[0]
		require.NoError(t, sessionStore.Get(cookie.Value, storedSession))
		assert.Equal(t, tenantDID, storedSession.TenantDID)
		assert.NotNil(t, capturedSession.Save)
	})
	t.Run("ok - existing session", func(t *testing.T) {
		instance, sessionStore := createInstance(t)
		expected, _ := createUserSession(tenantDID, time.Hour)
		_ = sessionStore.Put(sessionCookie.Value, expected)
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/"+tenantDID.String(), nil), httpResponse)
		echoContext.SetParamNames("did")
		echoContext.SetParamValues(tenantDID.String())
		echoContext.Request().AddCookie(&sessionCookie)

		var capturedSession *Data
		err := instance.Handle(func(c echo.Context) error {
			capturedSession, _ = Get(c.Request().Context())
			capturedSession.Wallet.Credentials = append(capturedSession.Wallet.Credentials, vc.VerifiableCredential{})
			return capturedSession.Save()
		})(echoContext)

		assert.NoError(t, err)
		assert.NotNil(t, capturedSession)
		assert.Equal(t, expected.TenantDID, capturedSession.TenantDID)
		assert.NotNil(t, capturedSession.Save)
		// Make sure no new cookie is set, which indicates session creation
		assert.Empty(t, httpResponse.Result().Cookies())
	})
	t.Run("skip", func(t *testing.T) {
		instance, _ := createInstance(t)
		instance.Skipper = func(_ echo.Context) bool {
			return true
		}
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/"+tenantDID.String(), nil), httpResponse)
		echoContext.SetParamNames("did")
		echoContext.SetParamValues(tenantDID.String())

		err := instance.Handle(func(c echo.Context) error {
			return nil
		})(echoContext)

		assert.NoError(t, err)
		assert.Empty(t, httpResponse.Result().Cookies())
	})
	t.Run("error - missing tenant DID", func(t *testing.T) {
		instance, _ := createInstance(t)
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/", nil), httpResponse)

		err := instance.Handle(func(c echo.Context) error {
			return nil
		})(echoContext)

		assert.Error(t, err)
		assert.Empty(t, httpResponse.Result().Cookies())
	})
	t.Run("error - invalid tenant DID", func(t *testing.T) {
		instance, _ := createInstance(t)
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/invalid", nil), httpResponse)
		echoContext.SetParamNames("did")
		echoContext.SetParamValues("invalid")

		err := instance.Handle(func(c echo.Context) error {
			return nil
		})(echoContext)

		assert.Error(t, err)
		assert.Empty(t, httpResponse.Result().Cookies())
	})
	t.Run("error - unknown session ID causes new session", func(t *testing.T) {
		instance, _ := createInstance(t)
		httpResponse := httptest.NewRecorder()
		echoServer := echo.New()
		echoContext := echoServer.NewContext(httptest.NewRequest(http.MethodGet, "/iam/"+tenantDID.String(), nil), httpResponse)
		echoContext.SetParamNames("did")
		echoContext.SetParamValues(tenantDID.String())
		// Session is not in storage, so error will be triggered and new session be created
		echoContext.Request().AddCookie(&sessionCookie)

		var capturedSession *Data
		err := instance.Handle(func(c echo.Context) error {
			var err error
			capturedSession, err = Get(c.Request().Context())
			return err
		})(echoContext)

		assert.NoError(t, err)
		assert.NotNil(t, capturedSession)
		assert.Equal(t, tenantDID, capturedSession.TenantDID)
		// Assert stored session
		assert.Len(t, httpResponse.Result().Cookies(), 1)
	})
}

func TestMiddleware_loadUserSession(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		instance, sessionStore := createInstance(t)
		expected, _ := createUserSession(tenantDID, time.Hour)
		_ = sessionStore.Put(sessionCookie.Value, expected)

		actualID, actualData, err := instance.loadUserSession((*testCookieReader)(&sessionCookie), tenantDID)
		require.NoError(t, err)
		assert.Equal(t, expected.TenantDID, actualData.TenantDID)
		assert.Equal(t, sessionCookie.Value, actualID)
	})
	t.Run("error - no session cookie", func(t *testing.T) {
		instance, _ := createInstance(t)

		_, actual, err := instance.loadUserSession((*testCookieReader)(nil), tenantDID)

		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - session not found", func(t *testing.T) {
		instance, _ := createInstance(t)

		_, actual, err := instance.loadUserSession((*testCookieReader)(&sessionCookie), tenantDID)

		assert.EqualError(t, err, "unknown or expired session")
		assert.Nil(t, actual)
	})
	t.Run("error - session belongs to a different tenant", func(t *testing.T) {
		instance, sessionStore := createInstance(t)
		expected, _ := createUserSession(tenantDID, time.Hour)
		expected.TenantDID = did.MustParseDID("did:web:someone-else")
		_ = sessionStore.Put(sessionCookie.Value, expected)

		_, actual, err := instance.loadUserSession((*testCookieReader)(&sessionCookie), tenantDID)

		assert.EqualError(t, err, "session belongs to another tenant (did:web:someone-else)")
		assert.Nil(t, actual)
	})
	t.Run("error - expired", func(t *testing.T) {
		instance, sessionStore := createInstance(t)
		expected := Data{
			TenantDID: tenantDID,
			Wallet: UserWallet{
				DID: userDID,
			},
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		_ = sessionStore.Put(sessionCookie.Value, expected)

		_, actual, err := instance.loadUserSession((*testCookieReader)(&sessionCookie), tenantDID)

		assert.EqualError(t, err, "expired session")
		assert.Nil(t, actual)
	})
}

func Test_generateUserSessionJWK(t *testing.T) {
	key, userDID, err := generateUserSessionJWK()
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotNil(t, userDID)
	assert.True(t, strings.HasPrefix(userDID.String(), "did:jwk:"))
}

func createInstance(t *testing.T) (Middleware, storage.SessionStore) {
	store := storage.NewTestInMemorySessionDatabase(t).GetStore(time.Hour, "sessions")
	return Middleware{
		Skipper: func(c echo.Context) bool {
			return false
		},
		TimeOut: time.Hour,
		Store:   store,
		CookiePath: func(tenantDID did.DID) string {
			return "/oauth2/" + tenantDID.String()
		},
	}, store
}

func TestMiddleware_createUserSessionCookie(t *testing.T) {
	cookie := Middleware{
		TimeOut: 30 * time.Minute,
	}.createUserSessionCookie("sessionID", "/iam/did:web:example.com:iam:123")
	assert.Equal(t, "/iam/did:web:example.com:iam:123", cookie.Path)
	assert.Equal(t, "__Secure-SID", cookie.Name)
	assert.Empty(t, cookie.Domain)
	assert.Empty(t, cookie.Expires)
	assert.Equal(t, 30*time.Minute, time.Duration(cookie.MaxAge)*time.Second)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	assert.True(t, cookie.Secure)
	assert.True(t, cookie.HttpOnly)
}
