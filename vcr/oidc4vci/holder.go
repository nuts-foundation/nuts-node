package oidc4vci

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
)

// HolderRegistry is a registry of Holder instances, used to keep track of holders in a multi-tenant environment.
type HolderRegistry struct {
	holderBaseURL string
}

func NewHolderFactory(holderBaseURL string, credentialStore vcrTypes.Writer) *HolderRegistry {
	// Add trailing slash if missing
	if holderBaseURL[len(holderBaseURL)-1] != '/' {
		holderBaseURL += "/"
	}
	return &HolderRegistry{
		holderBaseURL: holderBaseURL,
	}
}

func (h HolderRegistry) Get(did string) Holder {
	return &holder{
		did:        did,
		identifier: h.holderBaseURL + did,
	}
}

type Holder interface {
	Metadata() types.OAuth2ClientMetadata
	AcceptCredentialOffer(ctx context.Context, offer types.CredentialOffer) error
}

var _ Holder = (*holder)(nil)

type holder struct {
	did        string
	identifier string
}

func (h holder) Metadata() types.OAuth2ClientMetadata {
	return types.OAuth2ClientMetadata{
		// TODO: Shouldn't be "identifier" or something in there?
		CredentialOfferEndpoint: h.identifier + "/holder/oidc4vci/credential_offer",
	}
}

func (h holder) retrieveCredential(issuerClient IssuerClient, offer types.CredentialOffer, accessToken string) (*vc.VerifiableCredential, error) {
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
	return issuerClient.GetCredential(credentialRequest, accessToken)
}

func (h holder) AcceptCredentialOffer(ctx context.Context, offer types.CredentialOffer) error {
	issuerClient, err := NewIssuerClient(offer.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("unable to create issuer client: %w", err)
	}

	// TODO (non-prototype): store offer and perform these requests async
	//
	// Request the access token
	//
	accessTokenResponse, err := issuerClient.RequestAccessToken(types.PreAuthorizedCodeGrant, map[string]string{
		"pre-authorized_code": offer.Grants[types.PreAuthorizedCodeGrant].(map[string]interface{})["pre-authorized_code"].(string),
	})
	if err != nil {
		return fmt.Errorf("unable to request access token: %w", err)
	}

	fmt.Printf("CredentialOffer: %s, %v\n", h.identifier, offer)

	// TODO (non-prototype): we now do this in a goroutine to avoid blocking the issuer's process
	go func() {
		credential, err := h.retrieveCredential(issuerClient, offer, accessTokenResponse.AccessToken)
		if err != nil {
			log.Logger().WithError(err).Errorf("Unable to retrieve credential")
			return
		}
		// TODO (non-prototype): needs trying
		log.Logger().Infof("Received VC over OIDC4VCI, storing in VCR: %s", credential.ID.String())
		err = w.CredentialStore.StoreCredential(*credential, nil)
		if err != nil {
			println("Unable to store VC:", err.Error())
		}
	}()
}
