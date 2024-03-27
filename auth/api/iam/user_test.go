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
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
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

func TestWrapper_handleUserLanding(t *testing.T) {
	walletDID := did.MustParseDID("did:web:test.test:iam:123")
	verifierDID := did.MustParseDID("did:web:test.test:iam:456")
	userDetails := UserDetails{
		Id: "test",
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

	t.Run("OK", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL, _ := url.Parse("https://test.test/iam/123/user?token=token")
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().Return(&http.Request{Host: "test.test"})
		echoCtx.EXPECT().Redirect(http.StatusFound, expectedURL.String())
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
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().Return(&http.Request{Host: "test.test"})
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", redirectSession)
		require.NoError(t, err)
		ctx.iamClient.EXPECT().CreateAuthorizationRequest(gomock.Any(), walletDID, verifierDID, gomock.Any()).Return(nil, assert.AnError)

		err = ctx.client.handleUserLanding(echoCtx)

		assert.Error(t, err)
	})
}
