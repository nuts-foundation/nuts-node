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

package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// s2sMaxPresentationValidity defines the maximum validity of a presentation.
// This is to prevent replay attacks. The value is specified by Nuts RFC021, and excludes max. clock skew.
const s2sMaxPresentationValidity = 5 * time.Second

// s2sMaxClockSkew defines the maximum clock skew between nodes.
// The value is specified by Nuts RFC021.
const s2sMaxClockSkew = 5 * time.Second

// handleS2SAccessTokenRequest handles the /token request with vp_token bearer grant type, intended for service-to-service exchanges.
// It performs cheap checks first (parameter presence and validity, matching VCs to the presentation definition), then the more expensive ones (checking signatures).
func (r Wrapper) handleS2SAccessTokenRequest(ctx context.Context, issuer did.DID, scope string, submissionJSON string, assertionJSON string) (HandleTokenRequestResponseObject, error) {
	pexEnvelope, err := pe.ParseEnvelope([]byte(assertionJSON))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "assertion parameter is invalid: " + err.Error(),
		}
	}

	submission, err := pe.ParsePresentationSubmission([]byte(submissionJSON))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("invalid presentation submission: %s", err.Error()),
		}
	}

	var credentialSubjectID did.DID
	for _, presentation := range pexEnvelope.Presentations {
		if err := validateS2SPresentationMaxValidity(presentation); err != nil {
			return nil, err
		}
		if subjectDID, err := validatePresentationSigner(presentation, credentialSubjectID); err != nil {
			return nil, oauthError(oauth.InvalidRequest, err.Error())
		} else {
			credentialSubjectID = *subjectDID
		}
		if err := r.validatePresentationAudience(presentation, issuer); err != nil {
			return nil, err
		}
	}
	walletOwnerMapping, err := r.presentationDefinitionForScope(ctx, issuer, scope)
	if err != nil {
		return nil, err
	}
	pexConsumer := newPEXConsumer(walletOwnerMapping)
	if err := pexConsumer.fulfill(*submission, *pexEnvelope); err != nil {
		return nil, oauthError(oauth.InvalidRequest, err.Error())
	}

	for _, presentation := range pexEnvelope.Presentations {
		if err := r.validateS2SPresentationNonce(presentation); err != nil {
			return nil, err
		}
	}

	// Parse optional DPoP header
	httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
	dpopProof, err := dpopFromRequest(*httpRequest)
	if err != nil {
		return nil, err
	}

	// Check signatures of VP and VCs. Trust should be established by the Presentation Definition.
	for _, presentation := range pexEnvelope.Presentations {
		_, err = r.vcr.Verifier().VerifyVP(presentation, true, true, nil)
		if err != nil {
			return nil, oauth.OAuth2Error{
				Code:          oauth.InvalidRequest,
				Description:   "presentation(s) or contained credential(s) are invalid",
				InternalError: err,
			}
		}
	}

	// All OK, allow access
	response, err := r.createAccessToken(issuer, credentialSubjectID, time.Now(), scope, *pexConsumer, dpopProof)
	if err != nil {
		return nil, err
	}
	return HandleTokenRequest200JSONResponse(*response), nil
}

func resolveInputDescriptorValues(presentationDefinitions pe.WalletOwnerMapping, credentialMap map[string]vc.VerifiableCredential) (map[string]any, error) {
	fieldsMap := make(map[string]any)
	for _, definition := range presentationDefinitions {
		currFields, err := definition.ResolveConstraintsFields(credentialMap)
		if err != nil {
			return nil, oauth.OAuth2Error{
				Code:          oauth.ServerError,
				Description:   "unable to resolve Presentation Definition Constraints Fields",
				InternalError: err,
			}
		}
		for k, v := range currFields {
			if _, exists := fieldsMap[k]; exists {
				// Should be prevented by Presentation Definition author,
				// but still check this for security reasons.
				return nil, oauth.OAuth2Error{
					Code:        oauth.ServerError,
					Description: "duplicate mapped field in Presentation Definitions",
				}
			}
			fieldsMap[k] = v
		}
	}
	return fieldsMap, nil
}

// validateS2SPresentationMaxValidity checks that the presentation is valid for a reasonable amount of time.
func validateS2SPresentationMaxValidity(presentation vc.VerifiablePresentation) error {
	created := credential.PresentationIssuanceDate(presentation)
	expires := credential.PresentationExpirationDate(presentation)
	if created == nil || expires == nil {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation is missing creation or expiration date",
		}
	}
	if expires.Sub(*created) > s2sMaxPresentationValidity {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("presentation is valid for too long (max %s)", s2sMaxPresentationValidity),
		}
	}
	return nil
}

// validateS2SPresentationNonce checks if the nonce has been used before; 'nonce' claim for JWTs or LDProof's 'nonce' for JSON-LD.
func (r Wrapper) validateS2SPresentationNonce(presentation vc.VerifiablePresentation) error {
	nonce, err := extractNonce(presentation)
	if nonce == "" {
		return oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			InternalError: err,
			Description:   "presentation has invalid/missing nonce",
		}
	}
	nonceStore := r.storageEngine.GetSessionDatabase().GetStore(s2sMaxPresentationValidity+s2sMaxClockSkew, "s2s", "nonce")
	nonceError := nonceStore.Get(nonce, new(bool))
	if nonceError != nil && errors.Is(nonceError, storage.ErrNotFound) {
		// this is OK, nonce has not been used before
		nonceError = nil
	} else if nonceError == nil {
		// no store error: value was retrieved from store, meaning the nonce has been used before
		nonceError = oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation nonce has already been used",
		}
	}
	// Other error occurred. Keep error to report after storing nonce.

	// Regardless the result of the nonce checking, the nonce of the VP must not be used again.
	// So always store the nonce.
	if err := nonceStore.Put(nonce, true); err != nil {
		nonceError = errors.Join(fmt.Errorf("unable to store nonce: %w", err), nonceError)
	}
	return nonceError
}

// extractNonce extracts the nonce from the presentation.
// it uses the nonce from the JWT if available, otherwise it uses the nonce from the LD proof.
// returns empty string when no nonce is found.
func extractNonce(presentation vc.VerifiablePresentation) (string, error) {
	var nonce string
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		nonceRaw, _ := presentation.JWT().Get("nonce")
		nonce, _ = nonceRaw.(string)
	case vc.JSONLDPresentationProofFormat:
		proof, err := credential.ParseLDProof(presentation)
		if err != nil {
			return "", err
		}
		if proof.Nonce != nil && *proof.Nonce != "" {
			nonce = *proof.Nonce
		}
	}
	return nonce, nil
}
