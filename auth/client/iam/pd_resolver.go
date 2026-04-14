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
	"github.com/nuts-foundation/nuts-node/core"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// ResolvedPresentationDefinition contains a resolved PD and the scope to use in the token request.
type ResolvedPresentationDefinition struct {
	PresentationDefinition pe.PresentationDefinition
	// Scope is the scope string to include in the token request.
	// When resolved remotely, this is the original scope string (remote AS handles scope policy).
	// When resolved locally, this depends on the configured scope policy.
	Scope string
}

// PresentationDefinitionResolver resolves a PresentationDefinition for a given scope string.
// It uses the remote AS's PD endpoint when available, falling back to local policy resolution.
type PresentationDefinitionResolver struct {
	httpClient    HTTPClient
	policyBackend policy.PDPBackend
	strictMode    bool
}

// Resolve resolves a PresentationDefinition for the given scope string.
// If the remote AS metadata advertises a PD endpoint, the PD is fetched remotely
// and the full scope string is returned (remote AS handles scope policy).
// If no PD endpoint is available, the local policy backend is used and scope policy is enforced.
func (r *PresentationDefinitionResolver) Resolve(ctx context.Context, scope string, metadata oauth.AuthorizationServerMetadata) (*ResolvedPresentationDefinition, error) {
	if metadata.PresentationDefinitionEndpoint != "" {
		return r.resolveRemote(ctx, scope, metadata)
	}
	return r.resolveLocal(ctx, scope)
}

func (r *PresentationDefinitionResolver) resolveRemote(ctx context.Context, scope string, metadata oauth.AuthorizationServerMetadata) (*ResolvedPresentationDefinition, error) {
	parsedURL, err := core.ParsePublicURL(metadata.PresentationDefinitionEndpoint, r.strictMode)
	if err != nil {
		return nil, err
	}
	pdURL := nutsHttp.AddQueryParams(*parsedURL, map[string]string{
		"scope": scope,
	})
	pd, err := r.httpClient.PresentationDefinition(ctx, pdURL)
	if err != nil {
		return nil, err
	}
	return &ResolvedPresentationDefinition{
		PresentationDefinition: *pd,
		Scope:                  scope,
	}, nil
}

func (r *PresentationDefinitionResolver) resolveLocal(ctx context.Context, scope string) (*ResolvedPresentationDefinition, error) {
	match, err := r.policyBackend.FindCredentialProfile(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("local PD resolution failed: %w", err)
	}
	if match.ScopePolicy == policy.ScopePolicyProfileOnly && len(match.OtherScopes) > 0 {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: "scope policy 'profile-only' does not allow additional scopes",
		}
	}
	// Select the organization PD (default for current single-VP flow).
	// TODO: When #4080 adds two-VP support, this resolver will need to return multiple PDs.
	pd, ok := match.WalletOwnerMapping[pe.WalletOwnerOrganization]
	if !ok {
		return nil, fmt.Errorf("no organization presentation definition for scope %q", match.CredentialProfileScope)
	}
	return &ResolvedPresentationDefinition{
		PresentationDefinition: pd,
		Scope:                  scope,
	}, nil
}
