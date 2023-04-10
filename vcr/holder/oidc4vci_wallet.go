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

package holder

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
	"time"
)

type OIDCWallet interface {
	Metadata() oidc4vci.OAuth2ClientMetadata
	OfferCredential(ctx context.Context, offer oidc4vci.CredentialOffer) error
}

var _ OIDCWallet = (*wallet)(nil)

func NewOIDCWallet(did did.DID, identifier string, credentialStore vcrTypes.Writer, signer crypto.JWTSigner, resolver vdr.KeyResolver) OIDCWallet {
	return &wallet{
		did:             did,
		identifier:      identifier,
		credentialStore: credentialStore,
		signer:          signer,
		resolver:        resolver,
	}
}

type wallet struct {
	did             did.DID
	identifier      string
	credentialStore vcrTypes.Writer
	signer          crypto.JWTSigner
	resolver        vdr.KeyResolver
}

func (h wallet) Metadata() oidc4vci.OAuth2ClientMetadata {
	return oidc4vci.OAuth2ClientMetadata{
		CredentialOfferEndpoint: h.identifier + "/wallet/oidc4vci/credential_offer",
	}
}

func (h wallet) OfferCredential(ctx context.Context, offer oidc4vci.CredentialOffer) error {
	if len(offer.Credentials) != 1 {
		return errors.New("expected only 1 credential in credential offer")
	}

	issuerClient, err := oidc4vci.NewIssuerClient(ctx, &http.Client{}, offer.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("unable to create issuer client: %w", err)
	}

	// TODO: store offer and perform these requests async
	//       See https://github.com/nuts-foundation/nuts-node/issues/2040
	accessTokenResponse, err := issuerClient.RequestAccessToken(oidc4vci.PreAuthorizedCodeGrant, map[string]string{
		// TODO: The code below is unsafe, validate offered grants and then extract the pre-authorized code
		//       See https://github.com/nuts-foundation/nuts-node/issues/2038
		"pre-authorized_code": offer.Grants[0][oidc4vci.PreAuthorizedCodeGrant].(map[string]interface{})["pre-authorized_code"].(string),
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

	log.Logger().Debugf("CredentialOffer: %s, %v\n", h.identifier, offer)

	// TODO: we now do this in a goroutine to avoid blocking the issuer's process, needs more orchestration?
	//       See https://github.com/nuts-foundation/nuts-node/issues/2040
	go func() {
		retrieveCtx := context.Background()
		// TODO: How to deal with time-outs?
		//       See https://github.com/nuts-foundation/nuts-node/issues/2040
		retrieveCtx, cancel := context.WithTimeout(retrieveCtx, 10*time.Second)
		defer cancel()
		credential, err := h.retrieveCredential(retrieveCtx, issuerClient, offer, accessTokenResponse)
		if err != nil {
			log.Logger().WithError(err).Errorf("Unable to retrieve credential")
			return
		}
		log.Logger().Infof("Received VC over OIDC4VCI, storing in VCR: %s", credential.ID.String())
		err = h.credentialStore.StoreCredential(*credential, nil)
		if err != nil {
			log.Logger().WithError(err).Error("Unable to store VC")
		}
	}()
	return nil
}

func (h wallet) retrieveCredential(ctx context.Context, issuerClient oidc4vci.IssuerClient, offer oidc4vci.CredentialOffer, tokenResponse *oidc4vci.TokenResponse) (*vc.VerifiableCredential, error) {
	keyID, err := h.resolver.ResolveSigningKeyID(h.did, nil)
	// TODO: typ gets overwritten, audience somehow becomes an array.
	//		 See https://github.com/nuts-foundation/nuts-node/issues/2035
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

	credentialRequest := oidc4vci.CredentialRequest{
		CredentialDefinition: &offer.Credentials[0],
		Format:               oidc4vci.VerifiableCredentialJSONLDFormat,
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
