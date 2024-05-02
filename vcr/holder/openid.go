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
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"net/http"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// OpenIDHandler is the interface for handling issuer operations using OpenID4VCI.
type OpenIDHandler interface {
	// Metadata returns the OAuth2 client metadata for the wallet.
	Metadata() openid4vci.OAuth2ClientMetadata
	// HandleCredentialOffer handles a credential offer from an issuer.
	// It will try to retrieve the offered credential and store it.
	HandleCredentialOffer(ctx context.Context, offer openid4vci.CredentialOffer) error
}

var nowFunc = time.Now
var _ OpenIDHandler = (*openidHandler)(nil)

// NewOpenIDHandler creates an OpenIDHandler that tries to retrieve offered credentials, to store it in the given credential store.
func NewOpenIDHandler(did did.DID, identifier string, httpClient core.HTTPRequestDoer, credentialStore vcrTypes.Writer, signer crypto.JWTSigner, resolver resolver.KeyResolver) OpenIDHandler {
	return &openidHandler{
		did:                 did,
		identifier:          identifier,
		credentialStore:     credentialStore,
		signer:              signer,
		resolver:            resolver,
		httpClient:          httpClient,
		issuerClientCreator: openid4vci.NewIssuerAPIClient,
	}
}

type openidHandler struct {
	did                 did.DID
	identifier          string
	credentialStore     vcrTypes.Writer
	signer              crypto.JWTSigner
	resolver            resolver.KeyResolver
	issuerClientCreator func(ctx context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (openid4vci.IssuerAPIClient, error)
	httpClient          core.HTTPRequestDoer
}

func (h *openidHandler) Metadata() openid4vci.OAuth2ClientMetadata {
	return openid4vci.OAuth2ClientMetadata{
		CredentialOfferEndpoint: core.JoinURLPaths(h.identifier, "/openid4vci/credential_offer"),
	}
}

// HandleCredentialOffer handles a credential offer from an issuer.
// Error responses on the Credential Offer Endpoint are not defined in the OpenID4VCI spec,
// so these are inferred of whatever makes sense.
func (h *openidHandler) HandleCredentialOffer(ctx context.Context, offer openid4vci.CredentialOffer) error {
	// TODO: This check is too simplistic, there can be multiple credential offers,
	//       but the issuer should only request the one it's interested in.
	//       See https://github.com/nuts-foundation/nuts-node/issues/2049
	if len(offer.Credentials) != 1 {
		return openid4vci.Error{
			Err:        errors.New("there must be exactly 1 credential in credential offer"),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}
	offeredCredential := offer.Credentials[0]
	if offeredCredential.Format != vc.JSONLDCredentialProofFormat {
		return openid4vci.Error{
			Err:        fmt.Errorf("credential offer: unsupported format '%s'", offeredCredential.Format),
			Code:       openid4vci.UnsupportedCredentialType,
			StatusCode: http.StatusBadRequest,
		}
	}
	if err := offeredCredential.CredentialDefinition.Validate(true); err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("credential offer: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	preAuthorizedCode := getPreAuthorizedCodeFromOffer(offer)
	if preAuthorizedCode == "" {
		return openid4vci.Error{
			Err:        errors.New("couldn't find (valid) pre-authorized code grant in credential offer"),
			Code:       openid4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}

	issuerClient, err := h.issuerClientCreator(ctx, h.httpClient, offer.CredentialIssuer)
	if err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("unable to create issuer client: %w", err),
			Code:       openid4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}

	accessTokenResponse, err := issuerClient.RequestAccessToken(openid4vci.PreAuthorizedCodeGrant, map[string]string{
		"pre-authorized_code": preAuthorizedCode,
	})
	if err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("unable to request access token: %w", err),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	if accessTokenResponse.AccessToken == "" {
		return openid4vci.Error{
			Err:        errors.New("access_token is missing"),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	if accessTokenResponse.Get(oauth.CNonceParam) == "" {
		return openid4vci.Error{
			Err:        fmt.Errorf("%s is missing", oauth.CNonceParam),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	retrieveCtx := audit.Context(ctx, "app-openid4vci", "VCR/OpenID4VCI", "RetrieveCredential")
	credential, err := h.retrieveCredential(retrieveCtx, issuerClient, offeredCredential.CredentialDefinition, accessTokenResponse)
	if err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("unable to retrieve credential: %w", err),
			Code:       openid4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}
	if err = openid4vci.ValidateDefinitionWithCredential(*credential, *offeredCredential.CredentialDefinition); err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("received credential does not match offer: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusInternalServerError,
		}
	}
	log.Logger().
		WithField("credentialID", credential.ID).
		Infof("Received VC over OpenID4VCI")
	err = h.credentialStore.StoreCredential(*credential, nil)
	if err != nil {
		return fmt.Errorf("unable to store credential: %w", err)
	}
	return nil
}

func getPreAuthorizedCodeFromOffer(offer openid4vci.CredentialOffer) string {
	params, ok := offer.Grants[openid4vci.PreAuthorizedCodeGrant].(map[string]interface{})
	if !ok {
		return ""
	}
	preAuthorizedCode, ok := params["pre-authorized_code"].(string)
	if !ok {
		return ""
	}
	return preAuthorizedCode
}

func (h *openidHandler) retrieveCredential(ctx context.Context, issuerClient openid4vci.IssuerAPIClient, offer *openid4vci.CredentialDefinition, tokenResponse *oauth.TokenResponse) (*vc.VerifiableCredential, error) {
	keyID, _, err := h.resolver.ResolveKey(h.did, nil, resolver.NutsSigningKeyType)
	headers := map[string]interface{}{
		"typ": openid4vci.JWTTypeOpenID4VCIProof, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": keyID.String(),                    // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
	}
	claims := map[string]interface{}{
		"aud":   issuerClient.Metadata().CredentialIssuer,
		"iat":   nowFunc().Unix(),
		"nonce": tokenResponse.Get(oauth.CNonceParam),
	}

	proof, err := h.signer.SignJWT(ctx, claims, headers, keyID.String())
	if err != nil {
		return nil, fmt.Errorf("unable to sign request proof: %w", err)
	}

	credentialRequest := openid4vci.CredentialRequest{
		CredentialDefinition: offer,
		Format:               vc.JSONLDCredentialProofFormat,
		Proof: &openid4vci.CredentialRequestProof{
			Jwt:       proof,
			ProofType: "jwt",
		},
	}
	return issuerClient.RequestCredential(ctx, credentialRequest, tokenResponse.AccessToken)
}
