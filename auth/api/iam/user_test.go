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
	"github.com/nuts-foundation/nuts-node/mock"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapper_requestUserAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")

	t.Run("ok - user flow", func(t *testing.T) {
		userID := "test"
		body := &RequestAccessTokenJSONRequestBody{Verifier: verifierDID.String(), Scope: "first second", UserID: &userID}
		ctx := newTestClient(t)

		response, err := ctx.client.requestUserAccessToken(nil, walletDID, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		// assert token
		require.NoError(t, err)
		redirectResponse, ok := response.(RequestAccessToken302Response)
		assert.True(t, ok)
		assert.Contains(t, redirectResponse.Headers.Location, "https://test.test/iam/123/user?token=")

		// assert session
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		var target RedirectSession
		err = store.Get(redirectResponse.Headers.Location[37:], &target)
		require.NoError(t, err)
		assert.Equal(t, walletDID, target.OwnDID)

	})
	t.Run("error - wrong did type", func(t *testing.T) {
		walletDID := did.MustParseDID("did:test:123")
		ctx := newTestClient(t)
		body := &RequestAccessTokenJSONRequestBody{Verifier: "invalid"}

		_, err := ctx.client.requestUserAccessToken(nil, walletDID, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "unsupported DID method: test")
	})
}

func TestWrapper_handleUserLanding(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")
	userID := "user"
	redirectSession := RedirectSession{
		OwnDID: walletDID,
		AccessTokenRequest: RequestAccessTokenRequestObject{
			Body: &RequestAccessTokenJSONRequestBody{
				Scope:    "first second",
				UserID:   &userID,
				Verifier: verifierDID.String(),
			},
			Did: walletDID.String(),
		},
	}

	t.Run("OK", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL, _ := url.Parse("https://test.test/iam/123/user?token=token")
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().Return(&http.Request{Host: "test.test"})
		echoCtx.EXPECT().Redirect(http.StatusFound, expectedURL.String())
		ctx.relyingParty.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, "first second", gomock.Any()).Return(expectedURL, nil)
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", redirectSession)
		require.NoError(t, err)

		err = ctx.client.handleUserLanding(echoCtx)

		require.NoError(t, err)
		// check for deleted token
		err = store.Get("token", &RedirectSession{})
		assert.Error(t, err)
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
			AccessTokenRequest: RequestAccessTokenRequestObject{
				Body: &RequestAccessTokenJSONRequestBody{
					Scope:    "first second",
					UserID:   &userID,
					Verifier: "invalid",
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
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().Return(&http.Request{Host: "test.test"})
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", redirectSession)
		require.NoError(t, err)
		ctx.relyingParty.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, "first second", gomock.Any()).Return(nil, assert.AnError)

		err = ctx.client.handleUserLanding(echoCtx)

		assert.Error(t, err)
	})
}
