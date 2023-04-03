package oidc4vci

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
	"time"
)

type Wallet interface {
	Metadata() types.OAuth2ClientMetadata
	OfferCredential(ctx context.Context, offer types.CredentialOffer) error
}

var _ Wallet = (*wallet)(nil)

type wallet struct {
	did             did.DID
	identifier      string
	credentialStore vcrTypes.Writer
	signer          crypto.JWTSigner
	resolver        vdr.KeyResolver
}

func (h wallet) Metadata() types.OAuth2ClientMetadata {
	return types.OAuth2ClientMetadata{
		// TODO: Shouldn't be "identifier" or something in there?
		CredentialOfferEndpoint: h.identifier + "/wallet/oidc4vci/credential_offer",
	}
}

func (h wallet) retrieveCredential(ctx context.Context, issuerClient IssuerClient, offer types.CredentialOffer, tokenResponse *types.OIDCTokenResponse) (*vc.VerifiableCredential, error) {
	// TODO (non-prototype): now we re-use the resolved OIDC Provider Metadata,
	//                       but we should use resolve OIDC4VCI Credential Issuer Metadata and use its credential_endpoint instead

	keyID, err := h.resolver.ResolveSigningKeyID(h.did, nil)
	// Fixme: typ gets overwritten, audience somehow becomes an array.
	const proofType = "openid4vci-proof+jwt"
	headers := map[string]interface{}{
		"typ": proofType, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": keyID,     // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
	}
	claims := map[string]interface{}{
		"aud":   issuerClient.Metadata().CredentialIssuer,
		"iat":   time.Now().Unix(),
		"nonce": *tokenResponse.CNonce,
	}

	proof, err := h.signer.SignJWT(ctx, claims, headers, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to sign request proof: %w", err)
	}

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
			Jwt:       proof,
			ProofType: "jwt",
		},
	}
	return issuerClient.GetCredential(ctx, credentialRequest, tokenResponse.AccessToken)
}

func (h wallet) OfferCredential(ctx context.Context, offer types.CredentialOffer) error {
	issuerClient, err := NewIssuerClient(ctx, &http.Client{}, offer.CredentialIssuer)
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

	if accessTokenResponse.AccessToken == "" {
		return fmt.Errorf("access token is empty")
	}

	if accessTokenResponse.CNonce == nil {
		return fmt.Errorf("c_nonce is missing")
	}

	fmt.Printf("CredentialOffer: %s, %v\n", h.identifier, offer)

	// TODO (non-prototype): we now do this in a goroutine to avoid blocking the issuer's process
	go func() {
		// TODO (non-prototype): needs retrying
		retrieveCtx := context.Background()
		retrieveCtx, cancel := context.WithTimeout(retrieveCtx, 10*time.Second) // TODO: How to deal with time-outs?
		defer cancel()
		credential, err := h.retrieveCredential(retrieveCtx, issuerClient, offer, accessTokenResponse)
		if err != nil {
			log.Logger().WithError(err).Errorf("Unable to retrieve credential")
			return
		}
		log.Logger().Infof("Received VC over OIDC4VCI, storing in VCR: %s", credential.ID.String())
		err = h.credentialStore.StoreCredential(*credential, nil)
		if err != nil {
			println("Unable to store VC:", err.Error())
		}
	}()
	return nil
}
