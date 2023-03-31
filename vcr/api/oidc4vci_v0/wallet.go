package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"net/url"
)

func (w Wrapper) GetOAuth2ClientMetadata(_ context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error) {
	return GetOAuth2ClientMetadata200JSONResponse(w.HolderRegistry.GetWallet(request.Did).Metadata()), nil
}

func (w Wrapper) CredentialOffer(ctx context.Context, request CredentialOfferRequestObject) (CredentialOfferResponseObject, error) {
	offerParam, err := url.QueryUnescape(request.Params.CredentialOffer)
	if err != nil {
		return nil, core.InvalidInputError("unable to unescape credential offer query param")
	}
	offer := types.CredentialOffer{}
	if json.Unmarshal([]byte(offerParam), &offer) != nil {
		return nil, core.InvalidInputError("unable to unmarshal credential offer query param")
	}

	err = w.HolderRegistry.GetWallet(request.Did).OfferCredential(ctx, offer)
	if err != nil {
		return nil, err
	}

	return CredentialOffer202TextResponse("OK"), nil
}
