/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type testServerInterface struct {
	err error
}

func (t *testServerInterface) EncryptJwe(ctx echo.Context) error {
	return t.err
}
func (t *testServerInterface) DecryptJwe(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) GenerateKeyPair(_ echo.Context) error {
	return t.err
}

func (t *testServerInterface) SignJwt(_ echo.Context) error {
	return t.err
}

func (t *testServerInterface) SignJws(_ echo.Context) error {
	return t.err
}

var siws = []*ServerInterfaceWrapper{
	serverInterfaceWrapper(nil), serverInterfaceWrapper(errors.New("server error")),
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
		t.Run("Test BASE64 decoding of the payload attribute", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/", strings.NewReader(`{
			  "headers": {},
			  "payload": "eyJ0ZXN0IjogImNsYWltIn0=",
			  "kid": "did:nuts:..."
			}`))
			req.Header.Add("content-type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			var signRequest = &SignJwsRequest{}
			err := c.Bind(signRequest)
			assert.Equal(t, err, nil)
			assert.Equal(t, string(signRequest.Payload), "{\"test\": \"claim\"}")
		})
	}
}

func TestRegisterHandlers(t *testing.T) {
	t.Run("Registers routes for crypto module", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echo := core.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/internal/crypto/v1/sign_jwt", gomock.Any())
		echo.EXPECT().POST("/internal/crypto/v1/sign_jws", gomock.Any())
		echo.EXPECT().POST("/internal/crypto/v1/encrypt_jwe", gomock.Any())
		echo.EXPECT().POST("/internal/crypto/v1/decrypt_jwe", gomock.Any())

		RegisterHandlers(echo, &testServerInterface{})
	})
}

func serverInterfaceWrapper(err error) *ServerInterfaceWrapper {
	return &ServerInterfaceWrapper{
		Handler: &testServerInterface{err: err},
	}
}
