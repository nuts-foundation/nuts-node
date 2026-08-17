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
	"errors"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewScopeGranter(t *testing.T) {
	profile := func(p ScopePolicy, others ...string) *CredentialProfileMatch {
		return &CredentialProfileMatch{
			CredentialProfileScope: "profile-scope",
			ScopePolicy:            p,
			OtherScopes:            others,
		}
	}
	noEvaluator := func() ScopeEvaluator { return nil }

	t.Run("nil credential profile returns error", func(t *testing.T) {
		_, err := NewScopeGranter(nil, noEvaluator)
		require.Error(t, err)
	})
	t.Run("unsupported scope policy returns server_error", func(t *testing.T) {
		_, err := NewScopeGranter(profile("bogus"), noEvaluator)
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.ServerError, oauthErr.Code)
	})
	t.Run("dynamic without evaluator returns server_error", func(t *testing.T) {
		_, err := NewScopeGranter(profile(ScopePolicyDynamic), noEvaluator)
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.ServerError, oauthErr.Code)
	})
	t.Run("non-dynamic policies do not invoke resolveEvaluator", func(t *testing.T) {
		called := false
		resolve := func() ScopeEvaluator {
			called = true
			return nil
		}
		_, err := NewScopeGranter(profile(ScopePolicyProfileOnly), resolve)
		require.NoError(t, err)
		_, err = NewScopeGranter(profile(ScopePolicyPassthrough), resolve)
		require.NoError(t, err)
		assert.False(t, called, "resolveEvaluator should not be called for non-dynamic policies")
	})
}

func TestProfileOnlyGranter(t *testing.T) {
	t.Run("grants the credential profile scope when no other scopes are present", func(t *testing.T) {
		g, err := NewScopeGranter(&CredentialProfileMatch{
			CredentialProfileScope: "profile-scope",
			ScopePolicy:            ScopePolicyProfileOnly,
		}, nil)
		require.NoError(t, err)
		granted, err := g.Grant(context.Background(), GrantInput{})
		require.NoError(t, err)
		assert.Equal(t, "profile-scope", granted)
	})
	t.Run("constructor rejects extra scopes with invalid_scope (fail-fast before VP work)", func(t *testing.T) {
		_, err := NewScopeGranter(&CredentialProfileMatch{
			CredentialProfileScope: "profile-scope",
			ScopePolicy:            ScopePolicyProfileOnly,
			OtherScopes:            []string{"extra"},
		}, nil)
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.InvalidScope, oauthErr.Code)
	})
}

func TestPassthroughGranter(t *testing.T) {
	g, err := NewScopeGranter(&CredentialProfileMatch{
		CredentialProfileScope: "profile-scope",
		ScopePolicy:            ScopePolicyPassthrough,
		OtherScopes:            []string{"extra-a", "extra-b"},
	}, nil)
	require.NoError(t, err)
	granted, err := g.Grant(context.Background(), GrantInput{})
	require.NoError(t, err)
	assert.Equal(t, "profile-scope extra-a extra-b", granted)
}

func TestDynamicGranter(t *testing.T) {
	subjectDID := did.MustParseDID("did:web:example.com")
	match := &CredentialProfileMatch{
		CredentialProfileScope: "profile-scope",
		ScopePolicy:            ScopePolicyDynamic,
		OtherScopes:            []string{"extra-a", "extra-b"},
	}

	t.Run("forwards subject, profile, claims and full scope list to the evaluator", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ev := NewMockScopeEvaluator(ctrl)
		ev.EXPECT().EvaluateScopes(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, in ScopeEvaluationInput) (map[string]bool, error) {
				assert.Equal(t, "profile-scope", in.CredentialProfileScope)
				assert.Equal(t, []string{"profile-scope", "extra-a", "extra-b"}, in.Scopes)
				assert.Equal(t, subjectDID, in.SubjectDID)
				assert.Equal(t, map[string]any{"name": "Hospital"}, in.PresentationClaims)
				return map[string]bool{"profile-scope": true, "extra-a": true, "extra-b": true}, nil
			})
		g, err := NewScopeGranter(match, func() ScopeEvaluator { return ev })
		require.NoError(t, err)
		granted, err := g.Grant(context.Background(), GrantInput{
			SubjectDID:         subjectDID,
			PresentationClaims: map[string]any{"name": "Hospital"},
		})
		require.NoError(t, err)
		assert.Equal(t, "profile-scope extra-a extra-b", granted)
	})
	t.Run("excludes denied other scopes from the granted set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ev := NewMockScopeEvaluator(ctrl)
		ev.EXPECT().EvaluateScopes(gomock.Any(), gomock.Any()).Return(
			map[string]bool{"profile-scope": true, "extra-a": true, "extra-b": false}, nil,
		)
		g, _ := NewScopeGranter(match, func() ScopeEvaluator { return ev })
		granted, err := g.Grant(context.Background(), GrantInput{SubjectDID: subjectDID})
		require.NoError(t, err)
		assert.Equal(t, "profile-scope extra-a", granted)
	})
	t.Run("returns access_denied when the credential profile scope is denied", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ev := NewMockScopeEvaluator(ctrl)
		ev.EXPECT().EvaluateScopes(gomock.Any(), gomock.Any()).Return(
			map[string]bool{"profile-scope": false, "extra-a": true}, nil,
		)
		g, _ := NewScopeGranter(match, func() ScopeEvaluator { return ev })
		_, err := g.Grant(context.Background(), GrantInput{SubjectDID: subjectDID})
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.AccessDenied, oauthErr.Code)
	})
	t.Run("returns server_error when the evaluator fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ev := NewMockScopeEvaluator(ctrl)
		ev.EXPECT().EvaluateScopes(gomock.Any(), gomock.Any()).Return(nil, errors.New("pdp boom"))
		g, _ := NewScopeGranter(match, func() ScopeEvaluator { return ev })
		_, err := g.Grant(context.Background(), GrantInput{SubjectDID: subjectDID})
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.ServerError, oauthErr.Code)
		assert.Equal(t, "policy decision point unavailable", oauthErr.Description)
	})
}

// TestAuthZenScopeEvaluator covers the AuthZen-specific wire shape produced by the
// adapter. This is the boundary where the generic ScopeEvaluationInput is translated
// into the AuthZen Access Evaluations request format documented in PRD #4144.
func TestAuthZenScopeEvaluator(t *testing.T) {
	subjectDID := did.MustParseDID("did:web:hospital.example.com")
	claims := map[string]any{"name": "Hospital B.V.", "ura": "12345678"}
	in := ScopeEvaluationInput{
		CredentialProfileScope: "urn:nuts:medication-overview",
		Scopes:                 []string{"urn:nuts:medication-overview", "patient/Observation.read"},
		SubjectDID:             subjectDID,
		PresentationClaims:     claims,
	}

	t.Run("translates input to AuthZen request shape per PRD contract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := NewMockAuthZenEvaluator(ctrl)
		client.EXPECT().Evaluate(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, req authzen.EvaluationsRequest) (map[string]bool, error) {
				assert.Equal(t, "organization", req.Subject.Type)
				assert.Equal(t, subjectDID.String(), req.Subject.ID)
				assert.Equal(t, claims, req.Subject.Properties.Organization)
				assert.Equal(t, "request_scope", req.Action.Name)
				assert.Equal(t, "urn:nuts:medication-overview", req.Context.Policy)
				require.Len(t, req.Evaluations, 2)
				assert.Equal(t, "scope", req.Evaluations[0].Resource.Type)
				assert.Equal(t, "urn:nuts:medication-overview", req.Evaluations[0].Resource.ID)
				assert.Equal(t, "scope", req.Evaluations[1].Resource.Type)
				assert.Equal(t, "patient/Observation.read", req.Evaluations[1].Resource.ID)
				return map[string]bool{
					"urn:nuts:medication-overview": true,
					"patient/Observation.read":     false,
				}, nil
			})

		evaluator := NewAuthZenScopeEvaluator(client)
		decisions, err := evaluator.EvaluateScopes(context.Background(), in)

		require.NoError(t, err)
		assert.Equal(t, map[string]bool{
			"urn:nuts:medication-overview": true,
			"patient/Observation.read":     false,
		}, decisions)
	})
	t.Run("propagates client error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := NewMockAuthZenEvaluator(ctrl)
		client.EXPECT().Evaluate(gomock.Any(), gomock.Any()).Return(nil, errors.New("boom"))

		evaluator := NewAuthZenScopeEvaluator(client)
		_, err := evaluator.EvaluateScopes(context.Background(), in)

		require.EqualError(t, err, "boom")
	})
}
