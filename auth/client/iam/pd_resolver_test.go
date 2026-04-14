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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var testPD = pe.PresentationDefinition{
	Id: "test-pd",
	InputDescriptors: []*pe.InputDescriptor{
		{Id: "id1"},
	},
}

func TestPresentationDefinitionResolver_Resolve(t *testing.T) {
	t.Run("remote PD endpoint exists - fetches from remote and returns full scope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/presentation_definition", r.URL.Path)
			assert.Equal(t, "profile-scope extra-scope", r.URL.Query().Get("scope"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testPD)
		}))
		defer server.Close()

		resolver := &PresentationDefinitionResolver{
			httpClient: HTTPClient{
				strictMode: false,
				httpClient: client.New(10 * time.Second),
			},
		}
		metadata := oauth.AuthorizationServerMetadata{
			PresentationDefinitionEndpoint: server.URL + "/presentation_definition",
		}

		result, err := resolver.Resolve(context.Background(), "profile-scope extra-scope", metadata)

		require.NoError(t, err)
		assert.Equal(t, "test-pd", result.PresentationDefinition.Id)
		assert.Equal(t, "profile-scope extra-scope", result.Scope)
	})
	t.Run("no remote PD endpoint", func(t *testing.T) {
		metadata := oauth.AuthorizationServerMetadata{} // no PD endpoint

		t.Run("single scope, profile-only", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "profile-scope").Return(&policy.CredentialProfileMatch{
				CredentialProfileScope: "profile-scope",
				WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: testPD},
				ScopePolicy:            policy.ScopePolicyProfileOnly,
			}, nil)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			result, err := resolver.Resolve(context.Background(), "profile-scope", metadata)

			require.NoError(t, err)
			assert.Equal(t, "test-pd", result.PresentationDefinition.Id)
			assert.Equal(t, "profile-scope", result.Scope)
		})
		t.Run("multi-scope, profile-only rejects", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "profile-scope extra-scope").Return(&policy.CredentialProfileMatch{
				CredentialProfileScope: "profile-scope",
				OtherScopes:            []string{"extra-scope"},
				WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: testPD},
				ScopePolicy:            policy.ScopePolicyProfileOnly,
			}, nil)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			_, err := resolver.Resolve(context.Background(), "profile-scope extra-scope", metadata)

			assert.ErrorContains(t, err, "does not allow additional scopes")
		})
		t.Run("multi-scope, passthrough forwards all scopes", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "profile-scope extra-scope").Return(&policy.CredentialProfileMatch{
				CredentialProfileScope: "profile-scope",
				OtherScopes:            []string{"extra-scope"},
				WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: testPD},
				ScopePolicy:            policy.ScopePolicyPassthrough,
			}, nil)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			result, err := resolver.Resolve(context.Background(), "profile-scope extra-scope", metadata)

			require.NoError(t, err)
			assert.Equal(t, "test-pd", result.PresentationDefinition.Id)
			assert.Equal(t, "profile-scope extra-scope", result.Scope)
		})
		t.Run("multi-scope, dynamic forwards all scopes", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "profile-scope extra-scope").Return(&policy.CredentialProfileMatch{
				CredentialProfileScope: "profile-scope",
				OtherScopes:            []string{"extra-scope"},
				WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerOrganization: testPD},
				ScopePolicy:            policy.ScopePolicyDynamic,
			}, nil)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			result, err := resolver.Resolve(context.Background(), "profile-scope extra-scope", metadata)

			require.NoError(t, err)
			assert.Equal(t, "profile-scope extra-scope", result.Scope)
		})
		t.Run("unknown scope returns error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "unknown").Return(nil, policy.ErrNotFound)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			_, err := resolver.Resolve(context.Background(), "unknown", metadata)

			assert.ErrorIs(t, err, policy.ErrNotFound)
		})
		t.Run("no organization PD in wallet owner mapping returns error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPolicy := policy.NewMockPDPBackend(ctrl)
			mockPolicy.EXPECT().FindCredentialProfile(gomock.Any(), "user-only-scope").Return(&policy.CredentialProfileMatch{
				CredentialProfileScope: "user-only-scope",
				WalletOwnerMapping:     pe.WalletOwnerMapping{pe.WalletOwnerUser: testPD},
				ScopePolicy:            policy.ScopePolicyProfileOnly,
			}, nil)

			resolver := &PresentationDefinitionResolver{policyBackend: mockPolicy}
			_, err := resolver.Resolve(context.Background(), "user-only-scope", metadata)

			assert.ErrorContains(t, err, "no organization presentation definition")
		})
		t.Run("nil policy backend returns error", func(t *testing.T) {
			resolver := &PresentationDefinitionResolver{policyBackend: nil}
			_, err := resolver.Resolve(context.Background(), "any-scope", metadata)

			assert.ErrorContains(t, err, "policy backend")
		})
	})
	t.Run("remote PD endpoint returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		resolver := &PresentationDefinitionResolver{
			httpClient: HTTPClient{
				strictMode: false,
				httpClient: client.New(10 * time.Second),
			},
		}
		metadata := oauth.AuthorizationServerMetadata{
			PresentationDefinitionEndpoint: server.URL + "/presentation_definition",
		}

		_, err := resolver.Resolve(context.Background(), "scope", metadata)

		assert.Error(t, err)
	})
}
