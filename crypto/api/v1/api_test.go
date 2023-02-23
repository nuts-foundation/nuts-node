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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"testing"

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

func TestWrapper_EncryptJwe(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{"iss": "nuts"})
	t.Run("Corrupt to returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload:  payload,
			Receiver: "bananas",
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), 400)
		assert.Empty(t, jwe)
	})
	t.Run("Missing to returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload: payload,
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), 400)
		assert.Empty(t, jwe)
	})
	t.Run("Wrong kid to returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE", "kid": "did:nuts:12345#banana"}
		did, _ := ssi.ParseURI("did:nuts:12345")
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKeyAgreementKey(gomock.Any())
		ctx.keyResolver.EXPECT().ResolveRelationKeyID(gomock.Any(), types.KeyAgreement).Return(*did, nil)

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), 400)
		assert.Empty(t, jwe)
	})

	t.Run("error - EncryptJwe fails", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		did, _ := ssi.ParseURI("did:nuts:12345")
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("b00m!"))
		ctx.keyResolver.EXPECT().ResolveKeyAgreementKey(gomock.Any())

		ctx.keyResolver.EXPECT().ResolveRelationKeyID(gomock.Any(), types.KeyAgreement).Return(*did, nil)

		jwe, err := ctx.client.EncryptJwe(audit.TestContext(), EncryptJweRequestObject{Body: &request})

		assert.EqualError(t, err, "b00m!")
		assert.Empty(t, jwe)
	})

	t.Run("All OK returns 200, with DID, with payload", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		did, _ := ssi.ParseURI("did:nuts:12345")
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Headers:  headers,
			Payload:  payload,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKeyAgreementKey(gomock.Any())
		ctx.keyResolver.EXPECT().ResolveRelationKeyID(gomock.Any(), types.KeyAgreement).Return(*did, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("All OK returns 200, with Receiver:kid header[kid]:nil", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		kid := "did:nuts:12345#mykey-1"
		did, _ := ssi.ParseURI(kid)
		request := EncryptJweRequest{
			Receiver: kid,
			Headers:  headers,
			Payload:  payload,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveRelationKey(gomock.Any(), gomock.Any(), types.KeyAgreement).Return(*did, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("All OK returns 200, with Receiver:kid header[kid]:kid", func(t *testing.T) {
		ctx := newMockContext(t)
		kid := "did:nuts:12345#mykey-1"
		did, _ := ssi.ParseURI(kid)
		headers := map[string]interface{}{"typ": "JWE", "kid": kid}
		request := EncryptJweRequest{
			Receiver: kid,
			Headers:  headers,
			Payload:  payload,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveRelationKey(gomock.Any(), gomock.Any(), types.KeyAgreement).Return(*did, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("All OK returns 200, with Receiver:DID header[kid]:kid", func(t *testing.T) {
		ctx := newMockContext(t)
		kid := "did:nuts:12345#mykey-1"
		headers := map[string]interface{}{"typ": "JWE", "kid": kid}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Headers:  headers,
			Payload:  payload,
		}
		did, _ := ssi.ParseURI(kid)
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKeyAgreementKey(gomock.Any())
		ctx.keyResolver.EXPECT().ResolveRelationKeyID(gomock.Any(), types.KeyAgreement).Return(*did, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("All OK returns 200, with Receiver:DID header[kid]:nil", func(t *testing.T) {
		ctx := newMockContext(t)
		kid := "did:nuts:12345#mykey-1"
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Headers:  headers,
			Payload:  payload,
		}
		did, _ := ssi.ParseURI(kid)
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKeyAgreementKey(gomock.Any())
		ctx.keyResolver.EXPECT().ResolveRelationKeyID(gomock.Any(), types.KeyAgreement).Return(*did, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})

}

type mockContext struct {
	ctrl        *gomock.Controller
	keyStore    *crypto.MockKeyStore
	keyResolver *types.MockKeyResolver
	client      *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	keyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	client := &Wrapper{C: keyStore, K: keyResolver}

	return mockContext{
		ctrl:        ctrl,
		keyStore:    keyStore,
		keyResolver: keyResolver,
		client:      client,
	}
}
