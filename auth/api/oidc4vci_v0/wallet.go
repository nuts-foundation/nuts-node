package oidc4vci_v0

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/types"
	"net/url"
)

func (w Wrapper) CredentialOffer(ctx context.Context, request CredentialOfferRequestObject) (CredentialOfferResponseObject, error) {
	holderDID := request.Did
	offerParam, err := url.QueryUnescape(request.Params.CredentialOffer)
	if err != nil {
		return CredentialOffer400TextResponse("unable to unescape credential offer query param"), nil
	}
	offer := types.CredentialOffer{}
	if json.Unmarshal([]byte(offerParam), &offer) != nil {
		return CredentialOffer400TextResponse("unable to unmarshall credential offer query param"), nil
	}

	// TODO (non-prototype): store offer and perform these requests async
	//
	// Request the access token
	//
	accessTokenResponse, err := w.issuerClient.RequestAccessToken(types.PreAuthorizedCodeGrant, map[string]string{
		"pre-authorized_code": offer.Grants[types.PreAuthorizedCodeGrant].(map[string]interface{})["pre-authorized_code"].(string),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to request access token: %w", err)
	}

	fmt.Printf("CredentialOffer: %s, %v\n", holderDID, offer)

	// TODO (non-prototype): we now do this in a goroutine to avoid blocking the issuer's process
	go func() {
		credential, err := w.retrieveCredential(offer, accessTokenResponse.AccessToken)
		if err != nil {
			println("Unable to retrieve credential:", err.Error())
			return
		}
		// TODO (non-prototype): needs trying
		println("Received VC over OIDC4VCI, storing in VCR:", credential.ID.String())
		err = w.CredentialStore.StoreCredential(*credential, nil)
		if err != nil {
			println("Unable to store VC:", err.Error())
		}
	}()
	return CredentialOffer202TextResponse("OK"), nil
}

func (w Wrapper) retrieveCredential(offer types.CredentialOffer, accessToken string) (*vc.VerifiableCredential, error) {
	//
	// Request the Verifiable Credential, using the access token as Authorization header
	//
	// TODO (non-prototype): now we re-use the resolved OIDC Provider Metadata,
	//                       but we should use resolve OIDC4VCI Credential Issuer Metadata and use its credential_endpoint instead
	credentialRequest := types.CredentialRequest{
		// TODO (non-prototype): check there's credentials in the offer
		// TODO (non-prototype): support only 1 credential in the offer, or choose one (based on what?)
		CredentialDefinition: &offer.Credentials[0],
		// TODO (non-prototype): make this a constant?
		Format: "ldp_vc",
		// TODO (non-prototype): build actual proof
		Proof: &struct {
			Jwt       string `json:"jwt"`
			ProofType string `json:"proof_type"`
		}{
			Jwt:       "Trust me, I'm an engineer",
			ProofType: "jwt",
		},
	}
	return w.issuerClient.GetCredential(credentialRequest, accessToken)
}
