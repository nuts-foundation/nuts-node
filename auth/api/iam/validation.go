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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// validatePresentationSigner checks if the presenter of the VP is the same as the subject of the VCs being presented.
// All returned errors can be used as description in an OAuth2 error.
func validatePresentationSigner(presentation vc.VerifiablePresentation, expectedCredentialSubjectDID did.DID) (*did.DID, error) {
	if len(presentation.VerifiableCredential) == 0 {
		return credential.PresentationSigner(presentation)
	}
	subjectDID, err := credential.PresenterIsCredentialSubject(presentation)
	if err != nil {
		return nil, err
	}
	if subjectDID == nil {
		return nil, errors.New("presentation signer is not credential subject")
	}
	if !expectedCredentialSubjectDID.Empty() && !subjectDID.Equals(expectedCredentialSubjectDID) {
		return nil, errors.New("not all presentations have the same credential subject ID")
	}
	return subjectDID, nil
}

// validatePresentationAudience checks if the presentation audience (aud claim for JWTs, domain property for JSON-LD proofs) contains the issuer DID.
// it returns an OAuth2 error if the audience is missing or does not match the issuer.
func (r Wrapper) validatePresentationAudience(presentation vc.VerifiablePresentation, issuer did.DID) error {
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

// validatePresentationSubmission checks if the presentation submission is valid for the given scope:
//  1. Resolve presentation definition for the requested scope
//  2. Check submission against presentation and definition
//
// Errors are returned as OAuth2 errors.
func (r Wrapper) validatePresentationSubmission(ctx context.Context, authorizer did.DID, scope string, submission *pe.PresentationSubmission, pexEnvelope *pe.Envelope) (map[string]vc.VerifiableCredential, *PresentationDefinition, error) {
	mapping, err := r.presentationDefinitionForScope(ctx, authorizer, scope)
	if err != nil {
		return nil, nil, err
	}

	// Find the Presentation Definition referenced by the Submission in the mapping
	var definition *PresentationDefinition
	for _, curr := range mapping {
		if curr.Id == submission.DefinitionId {
			definition = &curr
		}
	}
	if definition == nil {
		return nil, nil, oauthError(oauth.InvalidRequest, "Presentation Submission references Presentation Definition that isn't requested")
	}
	credentialMap, err := submission.Validate(*pexEnvelope, *definition)
	if err != nil {
		return nil, nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   fmt.Sprintf("Presentation Submission does not conform to Presentation Definition (id=%s)", definition.Id),
			InternalError: err,
		}
	}
	return credentialMap, definition, err
}

func (r Wrapper) presentationDefinitionForScope(ctx context.Context, authorizer did.DID, scope string) (pe.WalletOwnerMapping, error) {
	mapping, err := r.policyBackend.PresentationDefinitions(ctx, authorizer, scope)
	if err != nil {
		if errors.Is(err, policy.ErrNotFound) {
			return nil, oauth.OAuth2Error{
				Code:          oauth.InvalidScope,
				InternalError: err,
				Description:   fmt.Sprintf("unsupported scope (%s) for presentation exchange: %s", scope, err.Error()),
			}
		}
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			InternalError: err,
			Description:   fmt.Sprintf("failed to retrieve presentation definition for scope (%s): %s", scope, err.Error()),
		}
	}
	return mapping, err
}
