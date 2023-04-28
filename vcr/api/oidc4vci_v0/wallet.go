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

package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
)

// GetOAuth2ClientMetadata returns the OAuth2 client metadata for the given DID.
func (w Wrapper) GetOAuth2ClientMetadata(_ context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	return GetOAuth2ClientMetadata200JSONResponse(w.VCR.GetOIDCWallet(*id).Metadata()), nil
}

// HandleCredentialOffer handles a credential offer for the given DID.
func (w Wrapper) HandleCredentialOffer(ctx context.Context, request HandleCredentialOfferRequestObject) (HandleCredentialOfferResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, errHolderOrIssuerNotFound
	}
	offer := oidc4vci.CredentialOffer{}
	if err := json.Unmarshal([]byte(request.Params.CredentialOffer), &offer); err != nil {
		// Note: error responses on the Credential Offer Endpoint are not specified in the OpenID4VCI spec.
		return nil, core.InvalidInputError("unable to unmarshal credential_offer: %w", err)
	}

	// TODO: If the wallet DID is unknown, it should still return 404 (like with an invalid DID).
	//       See https://github.com/nuts-foundation/nuts-node/issues/2056
	err = w.VCR.GetOIDCWallet(*id).HandleCredentialOffer(ctx, offer)
	if err != nil {
		return nil, err
	}

	return HandleCredentialOffer202TextResponse("OK"), nil
}
