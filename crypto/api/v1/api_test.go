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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

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
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, "kid").Return("", errors.New("b00m!"))

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
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, "kid").Return("token", nil)

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
	t.Run("Missing headers returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwsRequest{
			Kid:     "kid",
			Payload: payload,
		}

		token, err := ctx.client.SignJws(nil, SignJwsRequestObject{Body: &request})

		assert.EqualError(t, err, "invalid sign request: missing headers")
		assert.Empty(t, token)
	})
	t.Run("Missing payload returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SignJwsRequest{
			Kid:     "kid",
			Headers: headers,
		}

		token, err := ctx.client.SignJws(nil, SignJwsRequestObject{Body: &request})

		assert.EqualError(t, err, "invalid sign request: missing payload")
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
	t.Run("Corrupt receiver returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload:  payload,
			Headers:  map[string]interface{}{},
			Receiver: "bananas",
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("Missing receiver returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload: payload,
			Headers: map[string]interface{}{},
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid encrypt request: missing receiver")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("Empty receiver returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload:  payload,
			Headers:  map[string]interface{}{},
			Receiver: "",
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid encrypt request: missing receiver")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("Missing payload returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Receiver: "did:nuts:1234",
			Headers:  map[string]interface{}{},
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid encrypt request: missing payload")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("Missing headers returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := EncryptJweRequest{
			Payload:  payload,
			Receiver: "did:nuts:1234",
		}

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid encrypt request: missing headers")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("ResolveKey fails, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("", nil, errors.New("FAIL"))

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid receiver: FAIL")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("ResolveKey fails, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("", nil, errors.New("FAIL"))

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid receiver: FAIL")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("ResolveKeyByID fails, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345#key-1",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), resolver.KeyAgreement).Return("", errors.New("FAIL"))

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid receiver: FAIL")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("KeyAgreement key not found, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("", nil, resolver.ErrNotFound)

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "unable to locate receiver did:nuts:12345: unable to find the DID document")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("Key not found, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("", nil, resolver.ErrNotFound)

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "unable to locate receiver did:nuts:12345: unable to find the DID document")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("KeyAgreement key not found, returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345#key-1",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), resolver.KeyAgreement).Return("", resolver.ErrNotFound)

		jwe, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "unable to locate receiver did:nuts:12345#key-1: unable to find the DID document")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, jwe)
	})
	t.Run("KID header returns 400, with Receiver:kid header[kid]:kid", func(t *testing.T) {
		ctx := newMockContext(t)
		kid := "did:nuts:12345#mykey-1"
		headers := map[string]interface{}{"typ": "JWE", "kid": kid}
		request := EncryptJweRequest{
			Receiver: kid,
			Headers:  headers,
			Payload:  payload,
		}
		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "invalid encrypt request: kid header is not allowed, use the receiver field instead")
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
		assert.Empty(t, resp)
	})
	t.Run("error - EncryptJwe fails", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Payload:  payload,
			Headers:  headers,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("b00m!"))

		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("did:nuts:12345", nil, nil)

		jwe, err := ctx.client.EncryptJwe(audit.TestContext(), EncryptJweRequestObject{Body: &request})

		assert.EqualError(t, err, "failed to encrypt JWE: b00m!")
		assert.Empty(t, jwe)
	})

	t.Run("All OK returns 200, with DID, with payload", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		request := EncryptJweRequest{
			Receiver: "did:nuts:12345",
			Headers:  headers,
			Payload:  payload,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return("did:nuts:12345", nil, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("All OK returns 200, with Receiver:kid header[kid]:nil", func(t *testing.T) {
		ctx := newMockContext(t)
		headers := map[string]interface{}{"typ": "JWE"}
		kid := "did:nuts:12345#mykey-1"
		request := EncryptJweRequest{
			Receiver: kid,
			Headers:  headers,
			Payload:  payload,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), resolver.KeyAgreement).Return(kid, nil)

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
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return(kid, nil, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
	t.Run("Empty headers returns 200", func(t *testing.T) {
		ctx := newMockContext(t)
		did := "did:nuts:12345"
		request := EncryptJweRequest{
			Payload:  payload,
			Headers:  map[string]interface{}{},
			Receiver: did,
		}
		ctx.keyStore.EXPECT().EncryptJWE(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("jwe", nil)
		ctx.keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.KeyAgreement).Return(did, nil, nil)

		resp, err := ctx.client.EncryptJwe(nil, EncryptJweRequestObject{Body: &request})

		assert.Nil(t, err)
		assert.Equal(t, "jwe", string(resp.(EncryptJwe200TextResponse)))
	})
}

func TestWrapper_DecryptJwe(t *testing.T) {
	t.Run("Missing message returns 400", func(t *testing.T) {
		ctx := newMockContext(t)
		request := DecryptJweRequest{}

		_, err := ctx.client.DecryptJwe(nil, DecryptJweRequestObject{Body: &request})
		assert.Equal(t, err.(core.HTTPStatusCodeError).StatusCode(), http.StatusBadRequest)
	})
	t.Run("DecryptJWE fails, ", func(t *testing.T) {
		ctx := newMockContext(t)
		message := "encrypted"
		request := DecryptJweRequest{
			Message: message,
		}
		ctx.keyStore.EXPECT().DecryptJWE(gomock.Any(), "encrypted").Return(nil, nil, errors.New("b00m!"))
		resp, err := ctx.client.DecryptJwe(nil, DecryptJweRequestObject{Body: &request})
		assert.EqualError(t, err, "failed to decrypt JWE: b00m!")
		assert.Empty(t, resp)
	})
	t.Run("All OK returns 200, with Receiver:DID header[kid]:nil", func(t *testing.T) {
		ctx := newMockContext(t)
		message := "encrypted"
		request := DecryptJweRequest{
			Message: message,
		}
		ctx.keyStore.EXPECT().DecryptJWE(gomock.Any(), "encrypted").Return([]byte("unencrypted"), nil, nil)
		resp, err := ctx.client.DecryptJwe(nil, DecryptJweRequestObject{Body: &request})
		assert.Nil(t, err)
		assert.Equal(t, "unencrypted", string(resp.(DecryptJwe200JSONResponse).Body))
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	keyStore    *crypto.MockKeyStore
	keyResolver *resolver.MockKeyResolver
	client      *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	keyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	client := &Wrapper{C: keyStore, K: keyResolver}

	return mockContext{
		ctrl:        ctrl,
		keyStore:    keyStore,
		keyResolver: keyResolver,
		client:      client,
	}
}
