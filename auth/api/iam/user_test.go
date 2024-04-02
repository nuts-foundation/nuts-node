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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var walletDID = did.MustParseDID("did:web:example.com:iam:123")
var userDID = did.MustParseDID("did:jwk:really-a-jwk")

var sessionCookie = http.Cookie{
	Name:     "__Host-SID",
	Value:    "sessionID",
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteStrictMode,
}

func TestWrapper_handleUserLanding(t *testing.T) {
	userDetails := UserDetails{
		Id:   "test",
		Name: "John Doe",
		Role: "Caregiver",
	}
	redirectSession := RedirectSession{
		OwnDID: walletDID,
		AccessTokenRequest: RequestUserAccessTokenRequestObject{
			Body: &RequestUserAccessTokenJSONRequestBody{
				Scope:             "first second",
				PreauthorizedUser: &userDetails,
				Verifier:          verifierDID.String(),
			},
			Did: walletDID.String(),
		},
	}

	t.Run("new session", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL, _ := url.Parse("https://example.com/iam/123/user?token=token")
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().MinTimes(1).Return(&http.Request{Host: "example.com"})
		echoCtx.EXPECT().Redirect(http.StatusFound, expectedURL.String())
		var capturedCookie *http.Cookie
		echoCtx.EXPECT().Cookie(gomock.Any()).Return(nil, http.ErrNoCookie)
		echoCtx.EXPECT().SetCookie(gomock.Any()).DoAndReturn(func(cookie *http.Cookie) {
			capturedCookie = cookie
		})
		var employeeCredentialTemplate vc.VerifiableCredential
		var employeeCredentialOptions issuer.CredentialOptions
		ctx.vcIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, t vc.VerifiableCredential, o issuer.CredentialOptions) (*vc.VerifiableCredential, error) {
			employeeCredentialTemplate = t
			employeeCredentialOptions = o
			return &t, nil
		})
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, gomock.Any()).DoAndReturn(func(_ interface{}, did, verifier did.DID, modifier iam.RequestModifier) (*url.URL, error) {
			// check the parameters
			params := map[string]interface{}{}
			modifier(params)
			assert.Equal(t, "first second", params["scope"])
			assert.NotEmpty(t, params["state"])
			return expectedURL, nil
		})
		store := ctx.client.userRedirectStore()
		err := store.Put("token", redirectSession)
		require.NoError(t, err)

		err = ctx.client.handleUserLanding(echoCtx)

		require.NoError(t, err)
		// check security settings of session cookie
		assert.Equal(t, "/", capturedCookie.Path)
		assert.Equal(t, "__Host-SID", capturedCookie.Name)
		assert.Empty(t, capturedCookie.Domain)
		assert.Empty(t, capturedCookie.Expires)
		assert.NotEmpty(t, capturedCookie.MaxAge)
		assert.Equal(t, http.SameSiteStrictMode, capturedCookie.SameSite)
		assert.True(t, capturedCookie.Secure)
		assert.True(t, capturedCookie.HttpOnly)
		// check for issued EmployeeCredential in session wallet
		userSession := new(UserSession)
		require.NoError(t, ctx.client.userSessionStore().Get(capturedCookie.Value, userSession))
		assert.Equal(t, walletDID, userSession.TenantDID)
		require.Len(t, userSession.Wallet.Credentials, 1)
		// check the JWK can be parsed and contains a private key
		sessionKey, err := jwk.ParseKey(userSession.Wallet.JWK)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionKey.KeyID)
		assert.Equal(t, jwa.EC, sessionKey.KeyType())
		// check for details of issued EmployeeCredential
		assert.Equal(t, "EmployeeCredential", employeeCredentialTemplate.Type[0].String())
		employeeCredentialSubject := employeeCredentialTemplate.CredentialSubject[0].(map[string]string)
		assert.True(t, strings.HasPrefix(employeeCredentialSubject["id"], "did:jwk:"))
		assert.Equal(t, userDetails.Id, employeeCredentialSubject["identifier"])
		assert.Equal(t, userDetails.Name, employeeCredentialSubject["name"])
		assert.Equal(t, userDetails.Role, employeeCredentialSubject["roleName"])
		// check issuance options
		assert.False(t, employeeCredentialOptions.Public)
		assert.False(t, employeeCredentialOptions.Publish)
		assert.False(t, employeeCredentialOptions.WithStatusListRevocation)
		assert.Equal(t, vc.JWTCredentialProofFormat, employeeCredentialOptions.Format)

		// check for deleted token
		err = store.Get("token", &RedirectSession{})
		assert.Error(t, err)
	})
	t.Run("existing session", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL, _ := url.Parse("https://example.com/iam/123/user?token=token")
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().MinTimes(1).Return(&http.Request{Host: "example.com"})
		echoCtx.EXPECT().Redirect(http.StatusFound, expectedURL.String())
		echoCtx.EXPECT().Cookie(gomock.Any()).Return(&sessionCookie, nil)
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, gomock.Any()).Return(expectedURL, nil)
		require.NoError(t, ctx.client.userRedirectStore().Put("token", redirectSession))
		session := UserSession{
			TenantDID:         walletDID,
			PreAuthorizedUser: &userDetails,
			Wallet: UserWallet{
				DID: userDID,
			},
		}
		require.NoError(t, ctx.client.userSessionStore().Put(sessionCookie.Value, session))

		err := ctx.client.handleUserLanding(echoCtx)

		require.NoError(t, err)
	})
	t.Run("error - no token", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("")
		echoCtx.EXPECT().NoContent(http.StatusForbidden)

		err := ctx.client.handleUserLanding(echoCtx)

		require.NoError(t, err)
	})
	t.Run("error - token not found", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().NoContent(http.StatusForbidden)

		err := ctx.client.handleUserLanding(echoCtx)

		require.NoError(t, err)
	})
	t.Run("error - verifier did parse error", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", RedirectSession{
			OwnDID: walletDID,
			AccessTokenRequest: RequestUserAccessTokenRequestObject{
				Body: &RequestUserAccessTokenJSONRequestBody{
					Scope:             "first second",
					PreauthorizedUser: &userDetails,
					Verifier:          "invalid",
				},
				Did: walletDID.String(),
			},
		})
		require.NoError(t, err)

		err = ctx.client.handleUserLanding(echoCtx)

		require.Error(t, err)
	})
	t.Run("error - authorization request error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vcIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, t vc.VerifiableCredential, _ issuer.CredentialOptions) (*vc.VerifiableCredential, error) {
			// just return whatever template was given to avoid nil deref
			return &t, nil
		})
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().MinTimes(1).Return(&http.Request{Host: "example.com"})
		echoCtx.EXPECT().Cookie(gomock.Any()).Return(nil, http.ErrNoCookie)
		echoCtx.EXPECT().SetCookie(gomock.Any())
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", redirectSession)
		require.NoError(t, err)
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, gomock.Any()).Return(nil, assert.AnError)

		err = ctx.client.handleUserLanding(echoCtx)

		assert.Error(t, err)
	})
}

func TestWrapper_loadUserSession(t *testing.T) {
	user := &UserDetails{
		Id:   "test",
		Name: "John Doe",
		Role: "Caregiver",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		expected := UserSession{
			TenantDID:         walletDID,
			PreAuthorizedUser: user,
			Wallet: UserWallet{
				DID: userDID,
			},
		}
		_ = ctx.client.userSessionStore().Put(sessionCookie.Value, expected)
		ctrl := gomock.NewController(t)
		echoCtx := mock.NewMockContext(ctrl)
		echoCtx.EXPECT().Cookie(sessionCookie.Name).Return(&sessionCookie, nil)

		actual, err := ctx.client.loadUserSession(echoCtx, walletDID, user)

		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("error - no session cookie", func(t *testing.T) {
		ctx := newTestClient(t)
		ctrl := gomock.NewController(t)
		echoCtx := mock.NewMockContext(ctrl)
		echoCtx.EXPECT().Cookie(sessionCookie.Name).Return(nil, http.ErrNoCookie)

		actual, err := ctx.client.loadUserSession(echoCtx, walletDID, user)

		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - session not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctrl := gomock.NewController(t)
		echoCtx := mock.NewMockContext(ctrl)
		echoCtx.EXPECT().Cookie(sessionCookie.Name).Return(&sessionCookie, nil)

		actual, err := ctx.client.loadUserSession(echoCtx, walletDID, user)

		assert.EqualError(t, err, "unknown or expired session")
		assert.Nil(t, actual)
	})
	t.Run("error - session belongs to a different tenant", func(t *testing.T) {
		ctx := newTestClient(t)
		expected := UserSession{
			TenantDID: did.MustParseDID("did:web:someone-else"),
			Wallet: UserWallet{
				DID: userDID,
			},
		}
		_ = ctx.client.userSessionStore().Put(sessionCookie.Value, expected)
		ctrl := gomock.NewController(t)
		echoCtx := mock.NewMockContext(ctrl)
		echoCtx.EXPECT().Cookie(sessionCookie.Name).Return(&sessionCookie, nil)

		actual, err := ctx.client.loadUserSession(echoCtx, walletDID, user)

		assert.EqualError(t, err, "session belongs to another tenant (did:web:someone-else)")
		assert.Nil(t, actual)
	})
	t.Run("error - session belongs to a different pre-authorized user", func(t *testing.T) {
		ctx := newTestClient(t)
		expected := UserSession{
			TenantDID:         walletDID,
			PreAuthorizedUser: &UserDetails{Id: "someone-else"},
			Wallet: UserWallet{
				DID: userDID,
			},
		}

		_ = ctx.client.userSessionStore().Put(sessionCookie.Value, expected)
		ctrl := gomock.NewController(t)
		echoCtx := mock.NewMockContext(ctrl)
		echoCtx.EXPECT().Cookie(sessionCookie.Name).Return(&sessionCookie, nil)

		actual, err := ctx.client.loadUserSession(echoCtx, walletDID, user)

		assert.EqualError(t, err, "session belongs to another pre-authorized user")
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
