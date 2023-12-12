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
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// s2sMaxPresentationValidity defines the maximum validity of a presentation.
// This is to prevent replay attacks. The value is specified by Nuts RFC021, and excludes max. clock skew.
const s2sMaxPresentationValidity = 5 * time.Second

// s2sMaxClockSkew defines the maximum clock skew between nodes.
// The value is specified by Nuts RFC021.
const s2sMaxClockSkew = 5 * time.Second

// handleS2SAccessTokenRequest handles the /token request with vp_token bearer grant type, intended for service-to-service exchanges.
// It performs cheap checks first (parameter presence and validity, matching VCs to the presentation definition), then the more expensive ones (checking signatures).
func (r *Wrapper) handleS2SAccessTokenRequest(issuer did.DID, scope string, submissionJSON string, assertionJSON string) (HandleTokenRequestResponseObject, error) {
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
			return nil, err
		} else {
			credentialSubjectID = *subjectDID
		}
		if err := r.validatePresentationAudience(presentation, issuer); err != nil {
			return nil, err
		}
	}
	credentialMap, definition, err := r.validatePresentationSubmission(scope, submission, pexEnvelope)
	if err != nil {
		return nil, err
	}
	for _, presentation := range pexEnvelope.Presentations {
		if err := r.validateS2SPresentationNonce(presentation); err != nil {
			return nil, err
		}
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
	response, err := r.createS2SAccessToken(issuer, time.Now(), pexEnvelope.Presentations, *submission, *definition, scope, credentialSubjectID, credentialMap)
	if err != nil {
		return nil, err
	}
	return HandleTokenRequest200JSONResponse(*response), nil
}

func (r Wrapper) requestServiceAccessToken(ctx context.Context, requestHolder did.DID, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	// resolve verifier metadata
	requestVerifier, err := did.ParseDID(request.Body.Verifier)
	if err != nil {
		return nil, core.InvalidInputError("invalid verifier: %w", err)
	}
	_, _, err = r.vdr.Resolver().Resolve(*requestVerifier, nil)
	if err != nil {
		if errors.Is(err, resolver.ErrNotFound) {
			return nil, core.InvalidInputError("verifier not found: %w", err)
		}
		return nil, err
	}

	tokenResult, err := r.auth.RelyingParty().RequestRFC021AccessToken(ctx, requestHolder, *requestVerifier, request.Body.Scope)
	if err != nil {
		// this can be an internal server error, a 400 oauth error or a 412 precondition failed if the wallet does not contain the required credentials
		return nil, err
	}
	return RequestAccessToken200JSONResponse(*tokenResult), nil
}

func (r *Wrapper) createS2SAccessToken(issuer did.DID, issueTime time.Time, presentations []vc.VerifiablePresentation, submission pe.PresentationSubmission, definition PresentationDefinition, scope string, credentialSubjectDID did.DID, credentialMap map[string]vc.VerifiableCredential) (*oauth.TokenResponse, error) {
	fieldsMap, err := definition.ResolveConstraintsFields(credentialMap)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve Presentation Definition Constraints Fields: %w", err)
	}
	accessToken := AccessToken{
		Token:                          crypto.GenerateNonce(),
		Issuer:                         issuer.String(),
		ClientId:                       credentialSubjectDID.String(),
		IssuedAt:                       issueTime,
		Expiration:                     issueTime.Add(accessTokenValidity),
		Scope:                          scope,
		VPToken:                        presentations,
		PresentationDefinition:         &definition,
		PresentationSubmission:         &submission,
		InputDescriptorConstraintIdMap: fieldsMap,
	}
	err = r.accessTokenStore().Put(accessToken.Token, accessToken)
	if err != nil {
		return nil, fmt.Errorf("unable to store access token: %w", err)
	}
	expiresIn := int(accessTokenValidity.Seconds())
	return &oauth.TokenResponse{
		AccessToken: accessToken.Token,
		ExpiresIn:   &expiresIn,
		Scope:       &scope,
		TokenType:   "bearer",
	}, nil
}

// validatePresentationSubmission checks if the presentation submission is valid for the given scope:
//  1. Resolve presentation definition for the requested scope
//  2. Check submission against presentation and definition
func (r Wrapper) validatePresentationSubmission(scope string, submission *pe.PresentationSubmission, pexEnvelope *pe.Envelope) (map[string]vc.VerifiableCredential, *PresentationDefinition, error) {
	definition := r.auth.PresentationDefinitions().ByScope(scope)
	if definition == nil {
		return nil, nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", scope),
		}
	}

	credentialMap, err := submission.Validate(*pexEnvelope, *definition)
	if err != nil {
		return nil, nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "presentation submission does not conform to Presentation Definition",
			InternalError: err,
		}
	}
	return credentialMap, definition, err
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

// validatePresentationSigner checks if the presenter of the VP is the same as the subject of the VCs being presented.
func validatePresentationSigner(presentation vc.VerifiablePresentation, expectedCredentialSubjectDID did.DID) (*did.DID, error) {
	subjectDID, err := credential.PresenterIsCredentialSubject(presentation)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: err.Error(),
		}
	}
	if subjectDID == nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation signer is not credential subject",
		}
	}
	if !expectedCredentialSubjectDID.Empty() && !subjectDID.Equals(expectedCredentialSubjectDID) {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "not all presentations have the same credential subject ID",
		}
	}
	return subjectDID, nil
}

// validateS2SPresentationNonce checks if the nonce has been used before; 'nonce' claim for JWTs or LDProof's 'nonce' for JSON-LD.
func (r *Wrapper) validateS2SPresentationNonce(presentation vc.VerifiablePresentation) error {
	var nonce string
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		nonceRaw, _ := presentation.JWT().Get("nonce")
		nonce, _ = nonceRaw.(string)
		if nonce == "" {
			return oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "presentation has invalid/missing nonce",
			}
		}
	case vc.JSONLDPresentationProofFormat:
		proof, err := credential.ParseLDProof(presentation)
		if err != nil || proof.Nonce == nil || *proof.Nonce == "" {
			return oauth.OAuth2Error{
				Code:          oauth.InvalidRequest,
				InternalError: err,
				Description:   "presentation has invalid proof or nonce",
			}
		}
		nonce = *proof.Nonce
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

// validatePresentationAudience checks if the presentation audience (aud claim for JWTs, domain property for JSON-LD proofs) contains the issuer DID.
func (r *Wrapper) validatePresentationAudience(presentation vc.VerifiablePresentation, issuer did.DID) error {
	var audience []string
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		audience = presentation.JWT().Audience()
	case vc.JSONLDPresentationProofFormat:
		proof, err := credential.ParseLDProof(presentation)
		if err != nil {
			return err
		}
		if proof.Domain != nil {
			audience = []string{*proof.Domain}
		}
	}
	for _, aud := range audience {
		if aud == issuer.String() {
			return nil
		}
	}
	return oauth.OAuth2Error{
		Code:          oauth.InvalidRequest,
		Description:   "presentation audience/domain is missing or does not match",
		InternalError: fmt.Errorf("expected: %s, got: %v", issuer, audience),
	}
}

type AccessToken struct {
	Token string
	// Issuer and Subject of a token are always the same.
	Issuer string
	// TODO: should client_id be extracted to the PDPMap using the presentation definition?
	// ClientId is the DID of the entity requesting the access token. The Client needs to proof its id through proof-of-possession of the key for the DID.
	ClientId string
	// IssuedAt is the time the token is issued
	IssuedAt time.Time
	// Expiration is the time the token expires
	Expiration time.Time
	// Scope the token grants access to. Not necessarily the same as the requested scope
	Scope string
	// InputDescriptorConstraintIdMap maps the ID field of a PresentationDefinition input descriptor constraint to the value provided in the VPToken for the constraint.
	// The Policy Decision Point can use this map to make decisions without having to deal with PEX/VCs/VPs/SignatureValidation
	InputDescriptorConstraintIdMap map[string]any

	// additional fields to support unforeseen policy decision requirements

	// VPToken contains the VPs provided in the 'assertion' field of the s2s AT request.
	VPToken []VerifiablePresentation
	// PresentationSubmission as provided in the 'presentation_submission' field of the s2s AT request.
	PresentationSubmission *pe.PresentationSubmission
	// PresentationDefinition fulfilled to obtain the AT in the s2s flow.
	PresentationDefinition *pe.PresentationDefinition
}
