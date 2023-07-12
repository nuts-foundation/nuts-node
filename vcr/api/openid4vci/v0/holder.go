/*
 * Copyright (C) 2023 Nuts community
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
 *
 */

package v0

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
)

func (w Wrapper) getHolderHandler(ctx context.Context, holder string) (holder.OpenIDHandler, error) {
	holderDID, err := w.validateDIDIsOwned(ctx, holder)
	if err != nil {
		return nil, err
	}
	return w.VCR.GetOpenIDHolder(ctx, holderDID)
}

// GetOAuth2ClientMetadata returns the OAuth2 client metadata for the given DID.
func (w Wrapper) GetOAuth2ClientMetadata(ctx context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error) {
	wallet, err := w.getHolderHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	return GetOAuth2ClientMetadata200JSONResponse(wallet.Metadata()), nil
}

// HandleCredentialOffer handles a credential offer for the given DID.
func (w Wrapper) HandleCredentialOffer(ctx context.Context, request HandleCredentialOfferRequestObject) (HandleCredentialOfferResponseObject, error) {
	wallet, err := w.getHolderHandler(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	offer := openid4vci.CredentialOffer{}
	if err := json.Unmarshal([]byte(request.Params.CredentialOffer), &offer); err != nil {
		// Note: error responses on the Credential Offer Endpoint are not specified in the OpenID4VCI spec.
		return nil, core.InvalidInputError("unable to unmarshal credential_offer: %w", err)
	}
	err = wallet.HandleCredentialOffer(ctx, offer)
	if err != nil {
		return nil, err
	}
	return HandleCredentialOffer200JSONResponse{Status: openid4vci.CredentialOfferStatusReceived}, nil
}
