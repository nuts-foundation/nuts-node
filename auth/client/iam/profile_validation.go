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

package iam

import (
	"context"
	"fmt"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// loadAndValidateProfile fetches the credential profile for the requested scope, applies the scope policy,
// and verifies that the profile defines an organization PresentationDefinition (required by every local
// flow that fans out from VP1).
//
// Returns the credential profile and the resolved scope to forward to the AS. Returns an oauth.OAuth2Error
// (InvalidScope) when the profile is configured as profile-only but the request carries extra scopes; a
// plain error when the profile cannot be loaded or lacks the organization PD.
func loadAndValidateProfile(ctx context.Context, backend policy.PDPBackend, scope string) (*policy.CredentialProfileMatch, string, error) {
	if backend == nil {
		return nil, "", fmt.Errorf("local PD resolution requires a policy backend, but none is configured")
	}
	profile, err := backend.FindCredentialProfile(ctx, scope)
	if err != nil {
		return nil, "", fmt.Errorf("local PD resolution failed: %w", err)
	}
	if profile.ScopePolicy == policy.ScopePolicyProfileOnly && len(profile.OtherScopes) > 0 {
		return nil, "", oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: "scope policy 'profile-only' does not allow additional scopes",
		}
	}
	if _, ok := profile.WalletOwnerMapping[pe.WalletOwnerOrganization]; !ok {
		return nil, "", fmt.Errorf("no organization presentation definition for scope %q", profile.CredentialProfileScope)
	}
	resolvedScope := scope
	if profile.ScopePolicy == policy.ScopePolicyProfileOnly {
		resolvedScope = profile.CredentialProfileScope
	}
	return profile, resolvedScope, nil
}
