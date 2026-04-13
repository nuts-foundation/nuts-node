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

// CredentialProfileFunc is used to validate a presentation against a presentation definition, and extract the relevant information to be stored in the access token for policy decision and/or claims about the presentation.
type CredentialProfileFunc func(ctx context.Context, credentialProfile pe.WalletOwnerMapping, accessToken *AccessToken) error

// SubmissionProfileFunc returns a CredentialProfileFunc that validates a presentation against the given presentation submission and presentation exchange envelope,
// according to DIF Presentation Exchange.
func SubmissionProfileFunc(submission pe.PresentationSubmission, pexEnvelope pe.Envelope) CredentialProfileFunc {
	return func(ctx context.Context, credentialProfile pe.WalletOwnerMapping, accessToken *AccessToken) error {
		pexConsumer := newPEXConsumer(credentialProfile)
		if err := pexConsumer.fulfill(submission, pexEnvelope); err != nil {
			return oauthError(oauth.InvalidRequest, err.Error())
		}
		credentialMap, err := pexConsumer.credentialMap()
		if err != nil {
			return err
		}
		fieldsMap, err := resolveInputDescriptorValues(pexConsumer.RequiredPresentationDefinitions, credentialMap)
		if err != nil {
			return err
		}
		accessToken.PresentationSubmissions = pexConsumer.Submissions
		accessToken.PresentationDefinitions = pexConsumer.RequiredPresentationDefinitions
		err = accessToken.AddInputDescriptorConstraintIdMap(fieldsMap)
		if err != nil {
			// Message returned to the client in ambiguous on purpose for security; it indicates misconfiguration on the server's side.
			return oauthError(oauth.ServerError, "unable to fulfill presentation requirements", err)
		}
		accessToken.VPToken = append(accessToken.VPToken, pexEnvelope.Presentations...)
		return nil
	}
}

// BasicProfileFunc returns a CredentialProfileFunc that validates a presentation against the presentation definition(s).
// It does not consume a Presentation Submission.
func BasicProfileFunc(presentation VerifiablePresentation) CredentialProfileFunc {
	return func(ctx context.Context, credentialProfile pe.WalletOwnerMapping, accessToken *AccessToken) error {
		creds, inputDescriptors, err := credentialProfile[pe.WalletOwnerOrganization].Match(presentation.VerifiableCredential)
		if err != nil {
			return oauthError(oauth.InvalidRequest, fmt.Sprintf("presentation does not match presentation definition"), err)
		}
		// Collect input descriptor field ID -> value map
		// Will be ultimately returned as claims in the access token.
		credentialMap := make(map[string]vc.VerifiableCredential, len(inputDescriptors))
		for i, cred := range creds {
			credentialMap[inputDescriptors[i].Id] = cred
		}
		fieldMap, err := credentialProfile[pe.WalletOwnerOrganization].ResolveConstraintsFields(credentialMap)
		if err != nil {
			// This should be impossible, since the Match() function performs the same checks.
			return oauthError(oauth.ServerError, "unable to fulfill presentation requirements", err)
		}
		err = accessToken.AddInputDescriptorConstraintIdMap(fieldMap)
		if err != nil {
			// Message returned to the client in ambiguous on purpose for security; it indicates misconfiguration on the server's side.
			return oauthError(oauth.ServerError, "unable to fulfill presentation requirements", err)
		}
		accessToken.VPToken = append(accessToken.VPToken, presentation)
		return nil
	}
}

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
func (r Wrapper) validatePresentationAudience(presentation vc.VerifiablePresentation, subject string) error {
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
	expected := r.subjectToBaseURL(subject)
	for _, aud := range audience {
		if aud == expected.String() {
			return nil
		}
	}
	return oauth.OAuth2Error{
		Code:          oauth.InvalidRequest,
		Description:   "presentation audience/domain is missing or does not match",
		InternalError: fmt.Errorf("expected: %s, got: %v", expected.String(), audience),
	}
}

func (r Wrapper) presentationDefinitionForScope(ctx context.Context, scope string) (pe.WalletOwnerMapping, error) {
	mapping, err := r.policyBackend.PresentationDefinitions(ctx, scope)
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
