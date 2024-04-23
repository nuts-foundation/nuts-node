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
	"net/http"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

func (r *Wrapper) DPoPProof(ctx context.Context, requester did.DID, request http.Request, accessToken string) (string, error) {
	// find the key to sign the DPoP token with
	keyResolver := resolver.DIDKeyResolver{r.vdr.Resolver()}
	keyID, _, err := keyResolver.ResolveKey(requester, nil, resolver.AssertionMethod)
	if err != nil {
		return "", err
	}

	// create the DPoP token
	return r.keyStore.NewDPoP(ctx, request, keyID.String(), &accessToken)
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
