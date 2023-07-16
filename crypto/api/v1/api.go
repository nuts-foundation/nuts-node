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
	"context"
	crypt "crypto"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"

	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	C crypto.KeyStore
	K types.KeyResolver
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		crypto.ErrPrivateKeyNotFound: http.StatusBadRequest,
		types.ErrNotFound:            http.StatusNotFound,
		types.ErrKeyNotFound:         http.StatusNotFound,
	})
}

func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, crypto.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, crypto.ModuleName, operationID)
		},
	}))
}

func (signRequest SignJwtRequest) validate() error {
	if len(signRequest.Kid) == 0 {
		return errors.New("missing kid")
	}

	if len(signRequest.Claims) == 0 {
		return errors.New("missing claims")
	}

	return nil
}

func (signRequest SignJwsRequest) validate() error {
	if len(signRequest.Kid) == 0 {
		return errors.New("missing kid")
	}
	if signRequest.Headers == nil {
		return errors.New("missing headers")
	}
	if signRequest.Payload == nil {
		return errors.New("missing payload")
	}

	return nil
}

func (signRequest EncryptJweRequest) validate() error {
	if len(signRequest.Receiver) == 0 {
		return errors.New("missing receiver")
	}
	if signRequest.Headers == nil {
		return errors.New("missing headers")
	}
	if len(signRequest.Payload) == 0 {
		return errors.New("missing payload")
	}

	if _, ok := signRequest.Headers[jws.KeyIDKey]; ok {
		return errors.New("kid header is not allowed, use the receiver field instead")
	}

	// receiver can be either a DID or kid, so parse it as a DIDURL
	_, err := did.ParseDIDURL(signRequest.Receiver)
	if err != nil {
		return fmt.Errorf("invalid receiver: %w", err)
	}
	return nil
}
func (signRequest DecryptJweRequest) validate() error {
	if len(signRequest.Message) == 0 {
		return errors.New("missing message")
	}

	return nil
}

// SignJwt handles api calls for signing a Jwt
func (w *Wrapper) SignJwt(ctx context.Context, signRequest SignJwtRequestObject) (SignJwtResponseObject, error) {
	if err := signRequest.Body.validate(); err != nil {
		return nil, core.InvalidInputError("invalid sign request: %w", err)
	}
	sig, err := w.C.SignJWT(ctx, signRequest.Body.Claims, nil, signRequest.Body.Kid)
	if err != nil {
		return nil, err
	}
	return SignJwt200TextResponse(sig), nil
}

// SignJws handles api calls for signing a JWS
func (w *Wrapper) SignJws(ctx context.Context, request SignJwsRequestObject) (SignJwsResponseObject, error) {
	signRequest := request.Body
	if err := signRequest.validate(); err != nil {
		return nil, core.InvalidInputError("invalid sign request: %w", err)
	}
	detached := false
	if signRequest.Detached != nil {
		detached = *signRequest.Detached
	}

	headers := signRequest.Headers
	headers[jws.KeyIDKey] = signRequest.Kid // could've been set by caller, but make sure it's set correctly
	sig, err := w.C.SignJWS(ctx, signRequest.Payload, headers, signRequest.Kid, detached)
	if err != nil {
		return nil, err
	}

	return SignJws200TextResponse(sig), nil
}

// EncryptJwe handles api calls for encrypting JWE messages
func (w *Wrapper) EncryptJwe(ctx context.Context, request EncryptJweRequestObject) (EncryptJweResponseObject, error) {
	encryptRequest := request.Body
	if err := encryptRequest.validate(); err != nil {
		return nil, core.InvalidInputError("invalid encrypt request: %w", err)
	}
	receiver := encryptRequest.Receiver
	id, err := did.ParseDIDURL(receiver)
	if err != nil {
		return nil, err
	}
	key, keyID, err := w.resolvePublicKey(id)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrKeyNotFound) {
			return nil, core.InvalidInputError("unable to locate receiver %s: %w", receiver, err)
		}
		return nil, core.InvalidInputError("invalid receiver: %w", err)
	}

	headers := encryptRequest.Headers
	resolvedKid := keyID.String()
	// set / override kid in headers with actual used kid
	headers[jws.KeyIDKey] = resolvedKid

	jwe, err := w.C.EncryptJWE(ctx, encryptRequest.Payload, headers, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt JWE: %w", err)
	}
	return EncryptJwe200TextResponse(jwe), err
}

func (w *Wrapper) resolvePublicKey(id *did.DID) (key crypt.PublicKey, keyID ssi.URI, err error) {
	if id.IsURL() {
		// Assume it is a keyId
		now := time.Now()
		key, err = w.K.ResolveRelationKey(id.String(), &now, types.KeyAgreement)
		if err != nil {
			return nil, ssi.URI{}, err
		}
		keyID = id.URI()
	} else {
		// Assume it is a DID
		key, err = w.K.ResolveKeyAgreementKey(*id)
		if err != nil {
			return nil, ssi.URI{}, err
		}
		keyID, err = w.K.ResolveRelationKeyID(*id, types.KeyAgreement)
		if err != nil {
			return nil, ssi.URI{}, err
		}
	}
	return key, keyID, nil
}

// DecryptJwe handles api calls for decrypting JWE messages
func (w *Wrapper) DecryptJwe(ctx context.Context, request DecryptJweRequestObject) (DecryptJweResponseObject, error) {
	decryptRequest := request.Body
	if err := decryptRequest.validate(); err != nil {
		return nil, core.InvalidInputError("invalid decrypt request: %w", err)
	}
	jwe, headers, err := w.C.DecryptJWE(ctx, decryptRequest.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
	}
	return DecryptJwe200JSONResponse{Body: jwe, Headers: headers}, err
}
