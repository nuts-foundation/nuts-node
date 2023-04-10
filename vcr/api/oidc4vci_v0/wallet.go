package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
)

func (w Wrapper) GetOAuth2ClientMetadata(_ context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	return GetOAuth2ClientMetadata200JSONResponse(w.VCR.GetOIDCWallet(*id).Metadata()), nil
}

func (w Wrapper) OfferCredential(ctx context.Context, request OfferCredentialRequestObject) (OfferCredentialResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("invalid DID")
	}
	offer := oidc4vci.CredentialOffer{}
	if json.Unmarshal([]byte(request.Params.CredentialOffer), &offer) != nil {
		return nil, core.InvalidInputError("unable to unmarshal credential_offer")
	}
	if len(request.Params.CredentialOffer) != 1 {
		return nil, core.InvalidInputError("expected exactly 1 credential in credential offer")
	}

	err = w.VCR.GetOIDCWallet(*id).OfferCredential(ctx, offer)
	if err != nil {
		return nil, err
	}

	return OfferCredential202TextResponse("OK"), nil
}
