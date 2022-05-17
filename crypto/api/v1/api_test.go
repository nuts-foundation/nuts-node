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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/mock"
)

func TestWrapper_Preprocess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	w := &Wrapper{}
	ctx := mock.NewMockContext(ctrl)
	ctx.EXPECT().Set(core.StatusCodeResolverContextKey, w)
	ctx.EXPECT().Set(core.OperationIDContextKey, "foo")
	ctx.EXPECT().Set(core.ModuleNameContextKey, "Crypto")

	w.Preprocess("foo", ctx)
}

func Test_ErrorStatusCodes(t *testing.T) {
	assert.NotNil(t, (&Wrapper{}).ResolveStatusCode(nil))
}

func TestWrapper_SignJwt(t *testing.T) {
	t.Run("error - missing claim", func(t *testing.T) {
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

		assert.EqualError(t, err, "invalid sign request: missing claims")
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

		assert.EqualError(t, err, "invalid sign request: missing kid")
	})

	t.Run("error - SignJWT fails", func(t *testing.T) {
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
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), "kid").Return("", errors.New("b00m!"))

		err := ctx.client.SignJwt(ctx.echo)

		assert.EqualError(t, err, "b00m!")
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

	t.Run("error - bind fails", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("missing body in request"))

		err := ctx.client.SignJwt(ctx.echo)

		assert.EqualError(t, err, "missing body in request")
	})
}


func TestWrapper_Version(t *testing.T) {
	assert.Equal(t, 1, (&Wrapper{}).Version())
}

func TestWrapper_Name(t *testing.T) {
	assert.Equal(t, "Crypto", (&Wrapper{}).Name())
}

func TestWrapper_JsonSpec(t *testing.T) {
	data, err := (&Wrapper{}).JsonSpec()
	assert.NoError(t, err)
	assert.NotNil(t, data)
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
