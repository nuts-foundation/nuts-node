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
	"net/http"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
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
	// TODO: This check is too simplistic, there can be multiple credential_configuration_ids,
	//       but we only support one at a time.
	//       See https://github.com/nuts-foundation/nuts-node/issues/2049
	if len(offer.CredentialConfigurationIDs) != 1 {
		return openid4vci.Error{
			Err:        errors.New("there must be exactly 1 credential_configuration_id in credential offer"),
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

	// Resolve the credential configuration from the issuer metadata
	credentialConfigID := offer.CredentialConfigurationIDs[0]
	offeredCredential, err := h.resolveCredentialConfiguration(issuerClient.Metadata(), credentialConfigID)
	if err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("unable to resolve credential configuration: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}
	if offeredCredential.Format != vc.JSONLDCredentialProofFormat {
		return openid4vci.Error{
			Err:        fmt.Errorf("credential offer: unsupported format '%s'", offeredCredential.Format),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}
	if err := offeredCredential.CredentialDefinition.Validate(false); err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("credential offer: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	accessTokenResponse, err := issuerClient.RequestAccessToken(openid4vci.PreAuthorizedCodeGrant, map[string]string{
		"pre-authorized_code": preAuthorizedCode,
	})
	if err != nil {
		return openid4vci.Error{
			Err:        fmt.Errorf("unable to request access token: %w", err),
			Code:       openid4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}

	if accessTokenResponse.AccessToken == "" {
		return openid4vci.Error{
			Err:        errors.New("access_token is missing"),
			Code:       openid4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}

	retrieveCtx := audit.Context(ctx, "app-openid4vci", "VCR/OpenID4VCI", "RetrieveCredential")
	credential, err := h.retrieveCredential(retrieveCtx, issuerClient, credentialConfigID, accessTokenResponse)
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
	if offer.Grants == nil || offer.Grants.PreAuthorizedCode == nil {
		return ""
	}
	return offer.Grants.PreAuthorizedCode.PreAuthorizedCode
}

// resolveCredentialConfiguration resolves a credential_configuration_id to an OfferedCredential
// by looking it up in the issuer metadata.
func (h *openidHandler) resolveCredentialConfiguration(metadata openid4vci.CredentialIssuerMetadata, configID string) (*openid4vci.OfferedCredential, error) {
	config, ok := metadata.CredentialConfigurationsSupported[configID]
	if !ok {
		return nil, fmt.Errorf("credential_configuration_id '%s' not found in issuer metadata", configID)
	}

	format, ok := config["format"].(string)
	if !ok || format == "" {
		return nil, fmt.Errorf("credential configuration '%s' is missing 'format' field", configID)
	}
	credDefMap, _ := config["credential_definition"].(map[string]interface{})

	var credentialDef *openid4vci.CredentialDefinition
	if credDefMap != nil {
		credentialDef = &openid4vci.CredentialDefinition{}

		// Parse @context
		if contextRaw, ok := credDefMap["@context"].([]interface{}); ok {
			for _, c := range contextRaw {
				cStr, ok := c.(string)
				if !ok {
					return nil, fmt.Errorf("invalid @context entry: expected string, got %T", c)
				}
				u, err := ssi.ParseURI(cStr)
				if err != nil {
					return nil, fmt.Errorf("invalid @context URI %q: %w", cStr, err)
				}
				credentialDef.Context = append(credentialDef.Context, *u)
			}
		}

		// Parse type
		if typeRaw, ok := credDefMap["type"].([]interface{}); ok {
			for _, t := range typeRaw {
				tStr, ok := t.(string)
				if !ok {
					return nil, fmt.Errorf("invalid type entry: expected string, got %T", t)
				}
				u, err := ssi.ParseURI(tStr)
				if err != nil {
					return nil, fmt.Errorf("invalid type URI %q: %w", tStr, err)
				}
				credentialDef.Type = append(credentialDef.Type, *u)
			}
		}

		// Parse credentialSubject (optional in v1.0 metadata)
		if credSubject, ok := credDefMap["credentialSubject"].(map[string]interface{}); ok {
			credentialDef.CredentialSubject = credSubject
		}
	}

	return &openid4vci.OfferedCredential{
		Format:               format,
		CredentialDefinition: credentialDef,
	}, nil
}

func (h *openidHandler) retrieveCredential(ctx context.Context, issuerClient openid4vci.IssuerAPIClient, credentialConfigID string, tokenResponse *oauth.TokenResponse) (*vc.VerifiableCredential, error) {
	keyID, _, err := h.resolver.ResolveKey(h.did, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return nil, err
	}

	const maxAttempts = 2
	for attempt := range maxAttempts {
		headers := map[string]interface{}{
			"typ": openid4vci.JWTTypeOpenID4VCIProof,
			"kid": keyID,
		}
		claims := map[string]interface{}{
			"iss": h.did.String(),
			"aud": issuerClient.Metadata().CredentialIssuer,
			"iat": nowFunc().Unix(),
		}

		// Per v1.0 Section 7, fetch nonce from Nonce Endpoint when advertised
		if issuerClient.Metadata().NonceEndpoint != "" {
			nonceResponse, nonceErr := issuerClient.RequestNonce(ctx)
			if nonceErr != nil {
				return nil, fmt.Errorf("unable to request nonce: %w", nonceErr)
			}
			claims["nonce"] = nonceResponse.CNonce
		}

		proof, signErr := h.signer.SignJWT(ctx, claims, headers, keyID)
		if signErr != nil {
			return nil, fmt.Errorf("unable to sign request proof: %w", signErr)
		}

		credentialRequest := openid4vci.CredentialRequest{
			CredentialConfigurationID: credentialConfigID,
			Proofs: &openid4vci.CredentialRequestProofs{
				Jwt: []string{proof},
			},
		}
		credential, reqErr := issuerClient.RequestCredential(ctx, credentialRequest, tokenResponse.AccessToken)
		if reqErr != nil {
			// On invalid_nonce, fetch a fresh nonce and retry once (v1.0 Section 8.3.1.2)
			var protocolErr openid4vci.Error
			if attempt == 0 && errors.As(reqErr, &protocolErr) && protocolErr.Code == openid4vci.InvalidNonce {
				log.Logger().Debug("Received invalid_nonce, retrying with fresh nonce")
				continue
			}
			return nil, reqErr
		}
		return credential, nil
	}
	return nil, errors.New("credential request failed after nonce retry")
}
