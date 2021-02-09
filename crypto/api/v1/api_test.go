/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
 */

package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_SignJwt(t *testing.T) {
	t.Run("Missing claims returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		jsonRequest := SignJwtRequest{
			Kid: "kid",
		}
		jsonData, _ := json.Marshal(jsonRequest)

		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := ctx.client.SignJwt(ctx.echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing claims")
	})

	t.Run("Missing kid returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		jsonRequest := SignJwtRequest{
			Claims: map[string]interface{}{"iss": "nuts"},
		}
		jsonData, _ := json.Marshal(jsonRequest)

		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := ctx.client.SignJwt(ctx.echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing kid")
	})

	t.Run("Sign error returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		jsonRequest := SignJwtRequest{
			Kid:    "unknown",
			Claims: map[string]interface{}{"iss": "nuts"},
		}
		jsonData, _ := json.Marshal(jsonRequest)

		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), "unknown").Return("", errors.New("b00m!"))

		err := ctx.client.SignJwt(ctx.echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=b00m!")
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		jsonRequest := SignJwtRequest{
			Kid:    "kid",
			Claims: map[string]interface{}{"iss": "nuts"},
		}

		jsonData, _ := json.Marshal(jsonRequest)

		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), "kid").Return("token", nil)
		ctx.echo.EXPECT().String(http.StatusOK, "token")

		err := ctx.client.SignJwt(ctx.echo)

		assert.Nil(t, err)
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("missing body in request"))

		err := ctx.client.SignJwt(ctx.echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing body in request")
	})
}

func TestWrapper_PublicKey(t *testing.T) {
	at := time.Date(2020, 1, 1, 12, 30, 0, 0, time.UTC)
	timeString := at.Format(time.RFC3339)
	params := PublicKeyParams{
		At: &timeString,
	}

	t.Run("PublicKey API call returns 200", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		key := test.GenerateECKey()

		ctx.echo.EXPECT().Request().Return(&http.Request{})
		ctx.keyStore.EXPECT().GetPublicKey("kid", at).Return(key.Public(), nil)
		ctx.echo.EXPECT().String(http.StatusOK, gomock.Any())

		_ = ctx.client.PublicKey(ctx.echo, "kid", params)
	})

	t.Run("PublicKey API call returns JWK", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		key := test.GenerateECKey()

		ctx.echo.EXPECT().Request().Return(&http.Request{Header: http.Header{echo.HeaderAccept: []string{"application/json"}}})
		ctx.keyStore.EXPECT().GetPublicKey("kid", at).Return(key.Public(), nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		_ = ctx.client.PublicKey(ctx.echo, "kid", params)
	})

	t.Run("PublicKey API call returns 404 for unknown", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Request().Return(&http.Request{})
		ctx.keyStore.EXPECT().GetPublicKey("kid", at).Return(nil, storage.ErrNotFound)
		ctx.echo.EXPECT().NoContent(http.StatusNotFound)

		_ = ctx.client.PublicKey(ctx.echo, "kid", params)
	})

	t.Run("PublicKey API call returns 500 for other error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Request().Return(&http.Request{Header: http.Header{echo.HeaderAccept: []string{"application/json"}}})
		ctx.keyStore.EXPECT().GetPublicKey("kid", at).Return(nil, errors.New("b00m!"))

		err := ctx.client.PublicKey(ctx.echo, "kid", params)
		assert.Error(t, err)
	})

	t.Run("error - 400 for incorrect time format", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Request().Return(&http.Request{})
		ctx.echo.EXPECT().String(http.StatusBadRequest, "cannot parse 'b00m!' as RFC3339 time format")
		notAt := "b00m!"

		_ = ctx.client.PublicKey(ctx.echo, "kid", PublicKeyParams{At: &notAt})
	})
}

type mockContext struct {
	ctrl     *gomock.Controller
	echo     *mock.MockContext
	keyStore *crypto.MockKeyStore
	client   *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	keyStore := crypto.NewMockKeyStore(ctrl)
	client := &Wrapper{C: keyStore}

	return mockContext{
		ctrl:     ctrl,
		echo:     mock.NewMockContext(ctrl),
		keyStore: keyStore,
		client:   client,
	}
}
