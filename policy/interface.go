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

// AuthZenEvaluator evaluates OAuth2 scopes against an external AuthZen-compatible PDP.
// Defined here so PDPBackend can expose it without callers importing the authzen package directly.
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
	// AuthZenEvaluator returns the configured AuthZen evaluator for dynamic scope policy evaluation.
	// Returns nil when no AuthZen endpoint is configured.
	AuthZenEvaluator() AuthZenEvaluator
}
