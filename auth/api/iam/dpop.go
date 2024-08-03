/*
 * Nuts node
 * Copyright (C) 2024 Nuts community
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

package iam

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	nutsHash "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

func (r Wrapper) CreateDPoPProof(ctx context.Context, request CreateDPoPProofRequestObject) (CreateDPoPProofResponseObject, error) {
	// check method and url
	if request.Body.Htm == "" {
		return nil, core.InvalidInputError("missing method")
	}
	if request.Body.Htu == "" {
		return nil, core.InvalidInputError("missing url")
	}
	// check access token status
	if request.Body.Token == "" {
		return nil, core.InvalidInputError("missing token")
	}

	// extract DID from request path
	ownDID, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	// create new DPoP header
	httpRequest, err := http.NewRequest(request.Body.Htm, request.Body.Htu, nil)
	if err != nil {
		return nil, core.InvalidInputError(err.Error())
	}
	dpop, err := r.DPoPProof(ctx, *ownDID, *httpRequest, request.Body.Token)
	return CreateDPoPProof200JSONResponse{Dpop: dpop}, err
}

func (r Wrapper) ValidateDPoPProof(_ context.Context, request ValidateDPoPProofRequestObject) (ValidateDPoPProofResponseObject, error) {
	dpopToken, err := dpop.Parse(request.Body.DpopProof)
	if err != nil {
		reason := fmt.Sprintf("failed to parse DPoP header: %s", err.Error())
		return ValidateDPoPProof200JSONResponse{Reason: &reason}, nil
	}
	if ok, err := dpopToken.Match(request.Body.Thumbprint, request.Body.Method, request.Body.Url); !ok {
		reason := err.Error()
		return ValidateDPoPProof200JSONResponse{Reason: &reason}, nil
	}
	// check if ath claim matches hash of access_token
	ath, ok := dpopToken.Token.Get(dpop.ATHKey)
	if !ok {
		reason := "missing ath claim"
		return ValidateDPoPProof200JSONResponse{Reason: &reason}, nil
	}
	hash := nutsHash.SHA256Sum([]byte(request.Body.Token))
	if ath != base64.RawURLEncoding.EncodeToString(hash.Slice()) {
		reason := "ath/token claim mismatch"
		return ValidateDPoPProof200JSONResponse{Reason: &reason}, nil
	}
	// check if the jti is already used, if not add it to the store for the duration of the access token lifetime
	var target struct{}
	if err := r.useNonceOnceStore().Get(dpopToken.Token.JwtID(), &target); err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			log.Logger().WithError(err).Error("ValidateDPoPProof: failed to retrieve jti usage state")
			return nil, err
		}
		if err := r.useNonceOnceStore().Put(dpopToken.Token.JwtID(), target); err != nil {
			log.Logger().WithError(err).Error("ValidateDPoPProof: failed to store jti usage state")
			return nil, err
		}
	} else {
		// jti already used
		reason := "jti already used"
		return ValidateDPoPProof200JSONResponse{Reason: &reason}, nil
	}

	return ValidateDPoPProof200JSONResponse{Valid: true}, nil
}

func (r *Wrapper) DPoPProof(ctx context.Context, requester did.DID, request http.Request, accessToken string) (string, error) {
	// find the key to sign the DPoP token with
	keyResolver := resolver.DIDKeyResolver{Resolver: r.vdr.Resolver()}
	keyID, _, err := keyResolver.ResolveKey(requester, nil, resolver.AssertionMethod)
	if err != nil {
		return "", err
	}

	token := dpop.New(request)
	token.GenerateProof(accessToken)
	return r.jwtSigner.SignDPoP(ctx, *token, keyID)
}

func dpopFromRequest(httpRequest http.Request) (*dpop.DPoP, error) {
	dpopHeader := httpRequest.Header.Get("DPoP")
	// optional header
	if dpopHeader == "" {
		return nil, nil
	}
	// parse and validate DPoP header
	dpopProof, err := dpop.Parse(dpopHeader)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidDPopProof,
			Description:   "DPoP header is invalid",
			InternalError: err,
		}
	}
	return dpopProof, nil
}

// useNonceOnceStore is used to store nonces that are used once, e.g. DPoP jti
// it uses the access token validity as the expiration time
func (r Wrapper) useNonceOnceStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "nonceonce")
}
