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
	"errors"
	"testing"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestLoadAndValidateProfile(t *testing.T) {
	const requested = "first second"
	orgPD := pe.PresentationDefinition{Id: "org_pd"}

	t.Run("returns error when no policy backend is configured", func(t *testing.T) {
		_, _, err := loadAndValidateProfile(context.Background(), nil, requested)

		assert.ErrorContains(t, err, "local PD resolution requires a policy backend")
	})

	t.Run("wraps the policy backend error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backend := policy.NewMockPDPBackend(ctrl)
		backend.EXPECT().FindCredentialProfile(gomock.Any(), requested).Return(nil, errors.New("boom"))

		_, _, err := loadAndValidateProfile(context.Background(), backend, requested)

		assert.ErrorContains(t, err, "local PD resolution failed: boom")
	})

	t.Run("rejects extra scopes when policy is profile-only", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backend := policy.NewMockPDPBackend(ctrl)
		backend.EXPECT().FindCredentialProfile(gomock.Any(), requested).Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "first",
			OtherScopes:            []string{"second"},
			ScopePolicy:            policy.ScopePolicyProfileOnly,
			WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: orgPD},
		}, nil)

		_, _, err := loadAndValidateProfile(context.Background(), backend, requested)

		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.InvalidScope, oauthErr.Code)
		assert.Contains(t, oauthErr.Description, "scope policy 'profile-only' does not allow additional scopes")
	})

	t.Run("rejects when the organization PD is missing", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backend := policy.NewMockPDPBackend(ctrl)
		backend.EXPECT().FindCredentialProfile(gomock.Any(), requested).Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "first",
			ScopePolicy:            policy.ScopePolicyPassthrough,
			WalletOwnerMapping:     pe.WalletOwnerMapping{}, // no organization
		}, nil)

		_, _, err := loadAndValidateProfile(context.Background(), backend, requested)

		assert.ErrorContains(t, err, `no organization presentation definition for scope "first"`)
	})

	t.Run("collapses to credential profile scope when policy is profile-only and no extras", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backend := policy.NewMockPDPBackend(ctrl)
		backend.EXPECT().FindCredentialProfile(gomock.Any(), "first").Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "first",
			ScopePolicy:            policy.ScopePolicyProfileOnly,
			WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: orgPD},
		}, nil)

		profile, resolved, err := loadAndValidateProfile(context.Background(), backend, "first")

		require.NoError(t, err)
		assert.Equal(t, "first", resolved)
		assert.Equal(t, "first", profile.CredentialProfileScope)
	})

	t.Run("forwards the full input scope when policy is passthrough", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backend := policy.NewMockPDPBackend(ctrl)
		backend.EXPECT().FindCredentialProfile(gomock.Any(), requested).Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "first",
			OtherScopes:            []string{"second"},
			ScopePolicy:            policy.ScopePolicyPassthrough,
			WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: orgPD},
		}, nil)

		_, resolved, err := loadAndValidateProfile(context.Background(), backend, requested)

		require.NoError(t, err)
		assert.Equal(t, requested, resolved)
	})
}
