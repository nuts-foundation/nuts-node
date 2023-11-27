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
	"net/url"
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

// accessTokenValidity defines how long access tokens are valid.
// TODO: Might want to make this configurable at some point
const accessTokenValidity = 15 * time.Minute

// maxPresentationValidity defines the maximum validity of a presentation.
const maxPresentationValidity = 10 * time.Second

// handleS2SAccessTokenRequest handles the /token request with vp_token bearer grant type, intended for service-to-service exchanges.
// It performs cheap checks first (parameter presence and validity, matching VCs to the presentation definition), then the more expensive ones (checking signatures).
func (r *Wrapper) handleS2SAccessTokenRequest(issuer did.DID, params map[string]string) (HandleTokenRequestResponseObject, error) {
	submissionEncoded := params["presentation_submission"]
	scope := params[scopeParam]
	assertionEncoded := params["assertion"]
	if submissionEncoded == "" || scope == "" || assertionEncoded == "" {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "missing required parameters",
		}
	}

	// Unmarshal VP, which can be in URL-encoded JSON(LD) or JWT format.
	assertionDecoded, err := url.QueryUnescape(assertionEncoded)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "assertion parameter is invalid",
			InternalError: err,
		}
	}
	pexEnvelope, err := pe.ParseEnvelope([]byte(assertionDecoded))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "assertion parameter is invalid: " + err.Error(),
		}
	}

	// Unmarshal presentation submission
	submissionDecoded, err := url.QueryUnescape(submissionEncoded)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "presentation_submission parameter is invalid",
			InternalError: err,
		}
	}
	submission, err := pe.ParsePresentationSubmission([]byte(submissionDecoded))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("invalid presentation submission: %s", err.Error()),
		}
	}

	for _, presentation := range pexEnvelope.Presentations {
		if err := validatePresentationValidity(presentation); err != nil {
			return nil, err
		}
		if err := validatePresentationSigner(presentation); err != nil {
			return nil, err
		}
		if err := validatePresentationAudience(presentation, issuer); err != nil {
			return nil, err
		}
	}
	var definition *PresentationDefinition
	if definition, err = r.validatePresentationSubmission(scope, submission, pexEnvelope); err != nil {
		return nil, err
	}
	for _, presentation := range pexEnvelope.Presentations {
		if err := r.validatePresentationNonce(presentation); err != nil {
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
	response, err := r.createAccessToken(issuer, time.Now(), pexEnvelope.Presentations, *submission, *definition, scope)
	if err != nil {
		return nil, err
	}
	return HandleTokenRequest200JSONResponse(*response), nil
}

func (r *Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// resolve wallet
	requestHolder, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("did not found: %w", err)
	}
	isWallet, err := r.vdr.IsOwner(ctx, *requestHolder)
	if err != nil {
		return nil, err
	}
	if !isWallet {
		return nil, core.InvalidInputError("did not owned by this node: %w", err)
	}

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

	tokenResult, err := r.auth.RelyingParty().RequestRFC021AccessToken(ctx, *requestHolder, *requestVerifier, request.Body.Scope)
	if err != nil {
		// this can be an internal server error, a 400 oauth error or a 412 precondition failed if the wallet does not contain the required credentials
		return nil, err
	}
	return RequestAccessToken200JSONResponse(*tokenResult), nil
}

func (r *Wrapper) createAccessToken(issuer did.DID, issueTime time.Time, presentations []vc.VerifiablePresentation,
	submission pe.PresentationSubmission, definition PresentationDefinition, scope string) (*oauth.TokenResponse, error) {
	accessToken := AccessToken{
		Token:  crypto.GenerateNonce(),
		Issuer: issuer.String(),
		// TODO: set ClientId
		ClientId:               "",
		IssuedAt:               issueTime,
		Expiration:             issueTime.Add(accessTokenValidity),
		Scope:                  scope,
		VPToken:                presentations,
		PresentationDefinition: &definition,
		PresentationSubmission: &submission,
	}
	err := r.s2sAccessTokenStore().Put(accessToken.Token, accessToken)
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
func (r Wrapper) validatePresentationSubmission(scope string, submission *pe.PresentationSubmission, pexEnvelope *pe.Envelope) (*PresentationDefinition, error) {
	definition := r.auth.PresentationDefinitions().ByScope(scope)
	if definition == nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", scope),
		}
	}

	_, err := submission.Validate(*pexEnvelope, *definition)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "presentation submission does not conform to Presentation Definition",
			InternalError: err,
		}
	}
	return definition, err
}

// validatePresentationValidity checks that the presentation is valid for a reasonable amount of time.
func validatePresentationValidity(presentation vc.VerifiablePresentation) error {
	created := credential.PresentationIssuanceDate(presentation)
	expires := credential.PresentationExpirationDate(presentation)
	if created == nil || expires == nil {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation is missing creation or expiration date",
		}
	}
	if expires.Sub(*created) > maxPresentationValidity {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("presentation is valid for too long (max %s)", maxPresentationValidity),
		}
	}
	return nil
}

// validatePresentationSigner checks if the presenter of the VP is the same as the subject of the VCs being presented.
func validatePresentationSigner(presentation vc.VerifiablePresentation) error {
	ok, err := credential.PresenterIsCredentialSubject(presentation)
	if err != nil {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: err.Error(),
		}
	}
	if !ok {
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation signer is not credential subject",
		}
	}
	return nil
}

// validatePresentationNonce checks if the nonce has been used before; 'jti' claim for JWTs or LDProof's 'nonce' for JSON-LD.
func (r *Wrapper) validatePresentationNonce(presentation vc.VerifiablePresentation) error {
	var nonce string
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		nonce = presentation.JWT().JwtID()
		if nonce == "" {
			return oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "presentation is missing jti",
			}
		}
	case vc.JSONLDPresentationProofFormat:
		proof, err := credential.ParseLDProof(presentation)
		if err != nil || proof.Nonce == nil {
			return oauth.OAuth2Error{
				Code:          oauth.InvalidRequest,
				InternalError: err,
				Description:   "presentation has invalid proof or nonce",
			}
		}
		nonce = *proof.Nonce
	}

	nonceStore := r.storageEngine.GetSessionDatabase().GetStore(maxPresentationValidity, "s2s", "nonce")
	err := nonceStore.Get(nonce, new(bool))
	if !errors.Is(err, storage.ErrNotFound) {
		if err != nil {
			// unable to check nonce
			return err
		}
		return oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "presentation nonce has already been used",
		}
	}
	if err := nonceStore.Put(nonce, true); err != nil {
		return fmt.Errorf("unable to store nonce: %w", err)
	}
	return nil
}

func validatePresentationAudience(presentation vc.VerifiablePresentation, issuer did.DID) error {
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
		Code:        oauth.InvalidRequest,
		Description: "presentation audience is missing or does not match",
	}
}

func (r *Wrapper) s2sAccessTokenStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "s2s", "accesstoken")
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
