/*
 * Copyright (C) 2026 Nuts community
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

package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy/authzen"
)

// ScopeGranter computes the scopes to grant for an access token request, based on a
// credential profile match. There is one implementation per ScopePolicy mode.
type ScopeGranter interface {
	Grant(ctx context.Context, in GrantInput) (string, error)
}

// GrantInput carries the per-request data that ScopeGranter implementations may need.
// SubjectDID and PresentationClaims are only consumed by the dynamic granter; the
// other modes ignore them.
type GrantInput struct {
	SubjectDID         did.DID
	PresentationClaims map[string]any
}

// NewScopeGranter returns a ScopeGranter that implements credentialProfile.ScopePolicy.
// resolveEvaluator is invoked only when the scope policy is ScopePolicyDynamic; the
// other modes do not need a ScopeEvaluator and the function is not called.
func NewScopeGranter(credentialProfile *CredentialProfileMatch, resolveEvaluator func() ScopeEvaluator) (ScopeGranter, error) {
	if credentialProfile == nil {
		return nil, fmt.Errorf("credential profile is required")
	}
	switch credentialProfile.ScopePolicy {
	case ScopePolicyProfileOnly:
		// Fail fast: reject extra scopes at construction time so the caller can
		// short-circuit before doing expensive VP verification work.
		if len(credentialProfile.OtherScopes) > 0 {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidScope,
				Description: "scope policy 'profile-only' does not allow additional scopes",
			}
		}
		return profileOnlyGranter{credentialProfile: credentialProfile}, nil
	case ScopePolicyPassthrough:
		return passthroughGranter{credentialProfile: credentialProfile}, nil
	case ScopePolicyDynamic:
		evaluator := resolveEvaluator()
		if evaluator == nil {
			// Should be caught at startup by LocalPDP.Configure, but guard here defensively.
			return nil, oauth.OAuth2Error{
				Code:        oauth.ServerError,
				Description: "dynamic scope policy configured but no ScopeEvaluator available",
			}
		}
		return dynamicGranter{credentialProfile: credentialProfile, evaluator: evaluator}, nil
	default:
		return nil, oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: fmt.Sprintf("unsupported scope policy: %s", credentialProfile.ScopePolicy),
		}
	}
}

type profileOnlyGranter struct {
	credentialProfile *CredentialProfileMatch
}

func (g profileOnlyGranter) Grant(_ context.Context, _ GrantInput) (string, error) {
	return g.credentialProfile.CredentialProfileScope, nil
}

type passthroughGranter struct {
	credentialProfile *CredentialProfileMatch
}

func (g passthroughGranter) Grant(_ context.Context, _ GrantInput) (string, error) {
	scopes := append([]string{g.credentialProfile.CredentialProfileScope}, g.credentialProfile.OtherScopes...)
	return strings.Join(scopes, " "), nil
}

type dynamicGranter struct {
	credentialProfile *CredentialProfileMatch
	evaluator         ScopeEvaluator
}

func (g dynamicGranter) Grant(ctx context.Context, in GrantInput) (string, error) {
	allScopes := append([]string{g.credentialProfile.CredentialProfileScope}, g.credentialProfile.OtherScopes...)
	decisions, err := g.evaluator.EvaluateScopes(ctx, ScopeEvaluationInput{
		CredentialProfileScope: g.credentialProfile.CredentialProfileScope,
		Scopes:                 allScopes,
		SubjectDID:             in.SubjectDID,
		PresentationClaims:     in.PresentationClaims,
	})
	if err != nil {
		// Keep Description generic to avoid leaking PDP internals to the OAuth2 client.
		// Details remain available in InternalError for server-side logging.
		return "", oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "policy decision point unavailable",
			InternalError: err,
		}
	}
	if !decisions[g.credentialProfile.CredentialProfileScope] {
		return "", oauth.OAuth2Error{
			Code:        oauth.AccessDenied,
			Description: fmt.Sprintf("PDP denied credential profile scope %q", g.credentialProfile.CredentialProfileScope),
		}
	}
	granted := []string{g.credentialProfile.CredentialProfileScope}
	for _, s := range g.credentialProfile.OtherScopes {
		if decisions[s] {
			granted = append(granted, s)
		}
	}
	return strings.Join(granted, " "), nil
}

// NewAuthZenScopeEvaluator returns a ScopeEvaluator backed by an AuthZen-compatible PDP.
// The underlying AuthZenEvaluator is typically an *authzen.Client. The adapter is the
// single place that knows the AuthZen wire format; callers work in terms of the generic
// ScopeEvaluationInput shape.
func NewAuthZenScopeEvaluator(client AuthZenEvaluator) ScopeEvaluator {
	return authzenScopeEvaluator{client: client}
}

type authzenScopeEvaluator struct {
	client AuthZenEvaluator
}

func (a authzenScopeEvaluator) EvaluateScopes(ctx context.Context, in ScopeEvaluationInput) (map[string]bool, error) {
	request := authzen.EvaluationsRequest{
		Subject: authzen.Subject{
			Type: "organization",
			ID:   in.SubjectDID.String(),
			Properties: authzen.SubjectProperties{
				Organization: in.PresentationClaims,
			},
		},
		Action:      authzen.Action{Name: "request_scope"},
		Context:     authzen.EvaluationContext{Policy: in.CredentialProfileScope},
		Evaluations: make([]authzen.Evaluation, len(in.Scopes)),
	}
	for i, s := range in.Scopes {
		request.Evaluations[i] = authzen.Evaluation{Resource: authzen.Resource{Type: "scope", ID: s}}
	}
	return a.client.Evaluate(ctx, request)
}
