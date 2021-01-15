/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/mock"
)

type testServerInterface struct {
	err error
}

func (t *testServerInterface) GenerateKeyPair(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) PublicKey(ctx echo.Context, urn string) error {
	return t.err
}

func (t *testServerInterface) SignJwt(ctx echo.Context) error {
	return t.err
}

var siws = []*ServerInterfaceWrapper{
	serverInterfaceWrapper(nil), serverInterfaceWrapper(errors.New("Server error")),
}

func TestServerInterfaceWrapper_PublicKey(t *testing.T) {
	for _, siw := range siws {
		t.Run("PublicKey call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.GET, "/", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.SetParamNames("kid")
			c.SetParamValues("1")

			err := siw.PublicKey(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_SignJwt(t *testing.T) {
	for _, siw := range siws {
		t.Run("SignJWT call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.GET, "/", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.SignJwt(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestRegisterHandlers(t *testing.T) {
	t.Run("Registers routes for crypto module", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/internal/crypto/v1/sign_jwt", gomock.Any())
		echo.EXPECT().GET("/internal/crypto/v1/public_key/:kid", gomock.Any())

		RegisterHandlers(echo, &testServerInterface{})
	})
}

func serverInterfaceWrapper(err error) *ServerInterfaceWrapper {
	return &ServerInterfaceWrapper{
		Handler: &testServerInterface{err: err},
	}
}
