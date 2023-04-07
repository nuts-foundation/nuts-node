package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
)

func (w Wrapper) GetOAuth2ClientMetadata(_ context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOAuth2ClientMetadata200JSONResponse(w.VCR.GetOIDCWallet(*id).Metadata()), nil
}

func (w Wrapper) CredentialOffer(ctx context.Context, request CredentialOfferRequestObject) (CredentialOfferResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	offer := types.CredentialOffer{}
	if json.Unmarshal([]byte(request.Params.CredentialOffer), &offer) != nil {
		return nil, core.InvalidInputError("unable to unmarshal credential offer query param")
	}

	err = w.VCR.GetOIDCWallet(*id).OfferCredential(ctx, offer)
	if err != nil {
		return nil, err
	}

	return CredentialOffer202TextResponse("OK"), nil
}
