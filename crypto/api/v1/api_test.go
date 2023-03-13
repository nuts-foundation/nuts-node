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
	"testing"

	"github.com/nuts-foundation/nuts-node/audit"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto"
)

func Test_ErrorStatusCodes(t *testing.T) {
	assert.NotNil(t, (&Wrapper{}).ResolveStatusCode(nil))
}

func TestWrapper_SignJwt(t *testing.T) {
	t.Run("error - missing claim", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwtRequest{
			Kid: "kid",
		}

		token, err := ctx.client.SignJwt(nil, SignJwtRequestObject{Body: &request})

		assert.EqualError(t, err, "invalid sign request: missing claims")
		assert.Empty(t, token)
	})

	t.Run("Missing kid returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwtRequest{
			Claims: map[string]interface{}{"iss": "nuts"},
		}

		token, err := ctx.client.SignJwt(nil, SignJwtRequestObject{Body: &request})

		assert.EqualError(t, err, "invalid sign request: missing kid")
		assert.Empty(t, token)
	})

	t.Run("error - signJWT fails", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwtRequest{
			Kid:    "kid",
			Claims: map[string]interface{}{"iss": "nuts"},
		}
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), "kid").Return("", errors.New("b00m!"))

		token, err := ctx.client.SignJwt(nil, SignJwtRequestObject{Body: &request})

		assert.EqualError(t, err, "b00m!")
		assert.Empty(t, token)
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwtRequest{
			Kid:    "kid",
			Claims: map[string]interface{}{"iss": "nuts"},
		}
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), "kid").Return("token", nil)

		token, err := ctx.client.SignJwt(nil, SignJwtRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "token", string(token.(SignJwt200TextResponse)))
	})
}

func TestWrapper_SignJws(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
	headers := map[string]interface{}{"typ": "JWM"}

	t.Run("Missing kid returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwsRequest{
			Payload: payload,
		}

		token, err := ctx.client.SignJws(nil, SignJwsRequestObject{Body: &request})

		assert.EqualError(t, err, "invalid sign request: missing kid")
		assert.Empty(t, token)
	})

	t.Run("error - SignJWS fails", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwsRequest{
			Kid:     "kid",
			Payload: payload,
			Headers: headers,
		}
		ctx.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Any(), "kid", false).Return("", errors.New("b00m!"))

		token, err := ctx.client.SignJws(audit.TestContext(), SignJwsRequestObject{Body: &request})

		assert.EqualError(t, err, "b00m!")
		assert.Empty(t, token)
	})

	t.Run("All OK returns 200, with payload", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwsRequest{
			Kid:     "kid",
			Headers: headers,
			Payload: payload,
		}
		ctx.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Any(), "kid", false).Return("token", nil)

		token, err := ctx.client.SignJws(nil, SignJwsRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "token", string(token.(SignJws200TextResponse)))
	})

	t.Run("All OK returns 200, with payload, detached", func(t *testing.T) {
		ctx := newMockContext(t)
		detached := true
		request := SignJwsRequest{
			Kid:      "kid",
			Headers:  headers,
			Payload:  payload,
			Detached: &detached,
		}
		ctx.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Any(), "kid", true).Return("token", nil)

		token, err := ctx.client.SignJws(nil, SignJwsRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "token", string(token.(SignJws200TextResponse)))
	})
}

type mockContext struct {
	ctrl     *gomock.Controller
	keyStore *crypto.MockKeyStore
	client   *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	keyStore := crypto.NewMockKeyStore(ctrl)
	client := &Wrapper{C: keyStore}

	return mockContext{
		ctrl:     ctrl,
		keyStore: keyStore,
		client:   client,
	}
}
