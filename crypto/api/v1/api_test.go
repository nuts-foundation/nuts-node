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
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-go-test/io"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/stretchr/testify/assert"
)

type pubKeyMatcher struct {
}

func (p pubKeyMatcher) Matches(x interface{}) bool {
	s := x.(string)

	return strings.Contains(s, "-----BEGIN PUBLIC KEY-----")
}

func (p pubKeyMatcher) String() string {
	return "Public Key Matcher"
}

type jwkMatcher struct {
}

func (p jwkMatcher) Matches(x interface{}) bool {
	key := x.(jwk.Key)

	return key.KeyType() == jwa.EC
}

func (p jwkMatcher) String() string {
	return "JWK Matcher"
}

func TestWrapper_GenerateKeyPair(t *testing.T) {

	t.Run("GenerateKeyPairAPI call returns 200 with pub in PEM format", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().String(http.StatusOK, pubKeyMatcher{})

		se.GenerateKeyPair(echo)
	})

	t.Run("GenerateKeyPairAPI call returns 200 with pub in JWK format", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().JSON(http.StatusOK, jwkMatcher{})

		se.GenerateKeyPair(echo)
	})
}

func TestWrapper_SignJwt(t *testing.T) {
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
