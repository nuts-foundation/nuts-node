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
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/policy/authzen"
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
func (r Wrapper) handleS2SAccessTokenRequest(ctx context.Context, clientID string, subject string, scope string, submissionJSON string, assertionJSON string) (HandleTokenRequestResponseObject, error) {
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
		if err := r.validatePresentationAudience(presentation, subject); err != nil {
			return nil, err
		}
	}
	match, err := r.findCredentialProfile(ctx, scope)
	if err != nil {
		return nil, err
	}
	if match.ScopePolicy == policy.ScopePolicyProfileOnly && len(match.OtherScopes) > 0 {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: "scope policy 'profile-only' does not allow additional scopes",
		}
	}
	pexConsumer := newPEXConsumer(match.WalletOwnerMapping)
	if err := pexConsumer.fulfill(*submission, *pexEnvelope); err != nil {
		return nil, oauthError(oauth.InvalidRequest, err.Error())
	}

	for _, presentation := range pexEnvelope.Presentations {
		if err := r.validateS2SPresentationNonce(presentation); err != nil {
			return nil, err
		}
	}

	// Parse optional DPoP header
	httpRequest := ctx.Value(httpRequestContextKey{}).(*http.Request)
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
				Description:   verificationErrorDescription(err),
				InternalError: err,
			}
		}
	}

	// Compute granted scopes based on scope policy. Never pass through the raw input scope
	// directly — always derive granted scopes from the policy decision.
	grantedScope, err := r.grantedScopesForPolicy(ctx, match, credentialSubjectID, *pexConsumer)
	if err != nil {
		return nil, err
	}

	// All OK, allow access
	issuerURL := r.subjectToBaseURL(subject)
	response, err := r.createAccessToken(issuerURL.String(), clientID, time.Now(), grantedScope, *pexConsumer, dpopProof)
	if err != nil {
		return nil, err
	}
	return HandleTokenRequest200JSONResponse(*response), nil
}

// grantedScopesForPolicy returns the scopes to include in the access token based on the scope policy.
// Profile-only grants only the credential profile scope. Passthrough grants the credential profile
// scope plus all other requested scopes. Dynamic calls the configured AuthZen PDP for per-scope evaluation.
func (r Wrapper) grantedScopesForPolicy(ctx context.Context, match *policy.CredentialProfileMatch, subjectDID did.DID, pexState PEXConsumer) (string, error) {
	switch match.ScopePolicy {
	case policy.ScopePolicyProfileOnly:
		return match.CredentialProfileScope, nil
	case policy.ScopePolicyPassthrough:
		scopes := append([]string{match.CredentialProfileScope}, match.OtherScopes...)
		return strings.Join(scopes, " "), nil
	case policy.ScopePolicyDynamic:
		return r.evaluateDynamicScopes(ctx, match, subjectDID, pexState)
	default:
		return "", oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: fmt.Sprintf("unsupported scope policy: %s", match.ScopePolicy),
		}
	}
}

// evaluateDynamicScopes calls the AuthZen PDP to evaluate each requested scope.
// Returns the space-joined granted scopes. If the PDP denies the credential profile scope,
// the request is rejected. Other denied scopes are simply excluded from the granted set.
func (r Wrapper) evaluateDynamicScopes(ctx context.Context, match *policy.CredentialProfileMatch, subjectDID did.DID, pexState PEXConsumer) (string, error) {
	evaluator := r.policyBackend.AuthZenEvaluator()
	if evaluator == nil {
		// Should be caught at startup by policy.LocalPDP.Configure, but guard here defensively.
		return "", oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: "dynamic scope policy configured but no AuthZen evaluator available",
		}
	}
	credentialMap, err := pexState.credentialMap()
	if err != nil {
		return "", oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "failed to extract credentials for scope evaluation",
			InternalError: err,
		}
	}
	claims, err := resolveInputDescriptorValues(pexState.RequiredPresentationDefinitions, credentialMap)
	if err != nil {
		return "", err
	}
	allScopes := append([]string{match.CredentialProfileScope}, match.OtherScopes...)
	request := authzen.EvaluationsRequest{
		Subject: authzen.Subject{
			Type: "organization",
			ID:   subjectDID.String(),
			Properties: authzen.SubjectProperties{
				Organization: claims,
			},
		},
		Action:      authzen.Action{Name: "request_scope"},
		Context:     authzen.EvaluationContext{Policy: match.CredentialProfileScope},
		Evaluations: make([]authzen.Evaluation, len(allScopes)),
	}
	for i, s := range allScopes {
		request.Evaluations[i] = authzen.Evaluation{Resource: authzen.Resource{Type: "scope", ID: s}}
	}

	decisions, err := evaluator.Evaluate(ctx, request)
	if err != nil {
		// Keep Description generic to avoid leaking PDP internals to the OAuth2 client.
		// Details remain available in InternalError for server-side logging.
		return "", oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "policy decision point unavailable",
			InternalError: err,
		}
	}
	if !decisions[match.CredentialProfileScope] {
		return "", oauth.OAuth2Error{
			Code:        oauth.AccessDenied,
			Description: fmt.Sprintf("PDP denied credential profile scope %q", match.CredentialProfileScope),
		}
	}
	granted := []string{match.CredentialProfileScope}
	for _, s := range match.OtherScopes {
		if decisions[s] {
			granted = append(granted, s)
		}
	}
	return strings.Join(granted, " "), nil
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
	nonceError := r.s2sNonceStore().Get(nonce, new(bool))
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
	if err := r.s2sNonceStore().Put(nonce, true); err != nil {
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

// s2sNonceKey is used in the s2sNonceStore
var s2sNonceKey = []string{"s2s", "nonce"}

// s2sNonceStore is used by the authorization server for replay prevention by keeping track of used nonces in the s2s flow
func (r Wrapper) s2sNonceStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(s2sMaxPresentationValidity+s2sMaxClockSkew, s2sNonceKey...)
}
