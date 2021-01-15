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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_SignJwt(t *testing.T) {
	os.Setenv("NUTS_MODE", "server")
	defer os.Unsetenv("NUTS_MODE")
	core.NutsConfig().Load(&cobra.Command{})

	client := apiWrapper(t)

	publicKey, _ := client.C.GenerateKeyPair()
	kid, _ := util.Fingerprint(publicKey)

	t.Run("Missing claims returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			Kid: kid,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing claims")
	})

	t.Run("Missing kid returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			Claims: map[string]interface{}{"iss": "nuts"},
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing kid")
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			Kid: kid,
			Claims:      map[string]interface{}{"iss": "nuts"},
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().String(http.StatusOK, gomock.Any())

		err := client.SignJwt(echo)

		assert.Nil(t, err)
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing body in request")
	})
}

func TestWrapper_PublicKey(t *testing.T) {
	client := apiWrapper(t)

	publicKey, _ := client.C.GenerateKeyPair()
	kid, _ := util.Fingerprint(publicKey)

	t.Run("PublicKey API call returns 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().String(http.StatusOK, gomock.Any())

		_ = client.PublicKey(echo, kid)
	})

	t.Run("PublicKey API call returns JWK", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		_ = client.PublicKey(echo, kid)
	})

	t.Run("PublicKey API call returns 404 for unknown", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().NoContent(http.StatusNotFound)

		_ = client.PublicKey(echo, "not")
	})

	t.Run("PublicKey API call returns 404 for unknown, JWK requested", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().NoContent(http.StatusNotFound)

		_ = client.PublicKey(echo, "not")
	})
}

func apiWrapper(t *testing.T) *Wrapper {
	crypto := crypto.NewTestCryptoInstance(io.TestDirectory(t))

	return &Wrapper{C: crypto}
}
