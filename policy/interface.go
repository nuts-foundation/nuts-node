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

package policy

import (
	"context"
	"errors"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/policy/authzen"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// ModuleName is the name of the policy module.
const ModuleName = "policy"

// ErrNotFound is returned when no credential profile matches the requested scope.
var ErrNotFound = errors.New("not found")

// ErrAmbiguousScope is returned when multiple credential profile scopes are found in a single request.
var ErrAmbiguousScope = errors.New("multiple credential profile scopes found")

// ScopePolicy defines how extra scopes (beyond the credential profile scope) are handled.
type ScopePolicy string

const (
	// ScopePolicyProfileOnly only accepts the credential profile scope. Extra scopes cause an error.
	ScopePolicyProfileOnly ScopePolicy = "profile-only"
	// ScopePolicyPassthrough grants all requested scopes without evaluation.
	ScopePolicyPassthrough ScopePolicy = "passthrough"
	// ScopePolicyDynamic evaluates extra scopes via an external AuthZen PDP.
	ScopePolicyDynamic ScopePolicy = "dynamic"
)

// CredentialProfileMatch is the result of matching a scope string against the policy configuration.
// It contains the matched credential profile (WalletOwnerMapping + ScopePolicy) and the
// remaining scopes that did not match any credential profile.
type CredentialProfileMatch struct {
	// CredentialProfileScope is the scope that matched a credential profile.
	CredentialProfileScope string
	// WalletOwnerMapping contains the PresentationDefinitions per wallet owner type for the matched credential profile.
	WalletOwnerMapping pe.WalletOwnerMapping
	// ScopePolicy is the configured scope policy for the matched credential profile.
	ScopePolicy ScopePolicy
	// OtherScopes contains the scopes from the request that did not match any credential profile.
	OtherScopes []string
}

// ScopeEvaluationInput is the request passed to a ScopeEvaluator. It carries the data
// a PDP needs to make per-scope decisions for a single access token request.
type ScopeEvaluationInput struct {
	// CredentialProfileScope identifies which credential profile drives this request.
	// PDPs typically route to per-profile rule sets using this value.
	CredentialProfileScope string
	// Scopes is the full list of scopes to evaluate, starting with CredentialProfileScope.
	Scopes []string
	// SubjectDID is the DID of the entity whose credentials backed the request.
	SubjectDID did.DID
	// PresentationClaims are the role-grouped claims extracted from the validated
	// presentation(s). Currently only the organization role is populated.
	PresentationClaims map[string]any
}

// ScopeEvaluator evaluates the scopes of an access token request against an external
// policy decision point. It returns a per-scope decision map. The concrete backend
// (AuthZen, Rego, etc.) is an implementation detail behind this interface.
type ScopeEvaluator interface {
	EvaluateScopes(ctx context.Context, in ScopeEvaluationInput) (map[string]bool, error)
}

// AuthZenEvaluator is the low-level seam to an AuthZen-compatible PDP. It is satisfied
// by *authzen.Client. Most code should depend on ScopeEvaluator, which abstracts over
// the choice of PDP backend; AuthZenEvaluator stays exported so the AuthZen-backed
// ScopeEvaluator adapter can be wired up from outside this package (e.g. tests).
type AuthZenEvaluator interface {
	Evaluate(ctx context.Context, req authzen.EvaluationsRequest) (map[string]bool, error)
}

// PDPBackend is the interface for the policy backend.
// Both the remote and local policy backend implement this interface.
type PDPBackend interface {
	// FindCredentialProfile resolves a scope string against the policy configuration.
	// It parses the space-delimited scope string, identifies exactly one credential profile scope,
	// and returns the matched profile along with any remaining scopes.
	FindCredentialProfile(ctx context.Context, scope string) (*CredentialProfileMatch, error)
	// ScopeEvaluator returns the configured PDP evaluator for dynamic scope policy evaluation.
	// Returns nil when no PDP endpoint is configured.
	ScopeEvaluator() ScopeEvaluator
}
