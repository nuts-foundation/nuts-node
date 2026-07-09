/*
 * Nuts node
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
 */

package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenIDCredentialIssuerMetadata_ResolveCredentialConfigurationID(t *testing.T) {
	t.Run("ok - single match", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"UniversityDegreeCredential_jwt_vc_json": {
					Format:               "jwt_vc_json",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
				},
			},
		}

		id, err := metadata.ResolveCredentialConfigurationID("UniversityDegreeCredential")

		require.NoError(t, err)
		assert.Equal(t, "UniversityDegreeCredential_jwt_vc_json", id)
	})
	t.Run("ok - matches on vct for vc+sd-jwt/dc+sd-jwt formats", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"UniversityDegreeCredential_dc_sd_jwt": {
					Format: "dc+sd-jwt",
					Vct:    "UniversityDegreeCredential",
				},
			},
		}

		// Not a node-supported format, but the type is still located and reported accordingly.
		_, err := metadata.ResolveCredentialConfigurationID("UniversityDegreeCredential")

		assert.EqualError(t, err, `issuer offers "UniversityDegreeCredential" only in format(s): dc+sd-jwt`)
	})
	t.Run("ok - multiple matches in supported formats resolved by sorted candidate ID", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"ZZZ_UniversityDegreeCredential_jwt_vc_json": {
					Format:               "jwt_vc_json",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
				},
				"AAA_UniversityDegreeCredential_ldp_vc": {
					Format:               "ldp_vc",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
				},
			},
		}

		// Both formats are supported; there is no format ranking between them, so the
		// lexicographically smallest candidate ID wins.
		id, err := metadata.ResolveCredentialConfigurationID("UniversityDegreeCredential")

		require.NoError(t, err)
		assert.Equal(t, "AAA_UniversityDegreeCredential_ldp_vc", id)
	})
	t.Run("error - no matches at all", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"UniversityDegreeCredential_jwt_vc_json": {
					Format:               "jwt_vc_json",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
				},
			},
		}

		_, err := metadata.ResolveCredentialConfigurationID("UnknownCredential")

		assert.EqualError(t, err, `issuer does not offer a credential of type "UnknownCredential"`)
	})
	t.Run("error - matches only in unsupported format(s)", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"MdocOnlyCredential_mso_mdoc": {
					Format:               "mso_mdoc",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "MdocOnlyCredential"}},
				},
			},
		}

		_, err := metadata.ResolveCredentialConfigurationID("MdocOnlyCredential")

		assert.EqualError(t, err, `issuer offers "MdocOnlyCredential" only in format(s): mso_mdoc`)
	})
	t.Run("error - unsupported formats are listed sorted and deduplicated", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"1": {Format: "mso_mdoc", CredentialDefinition: &CredentialDefinition{Type: []string{"SomeCredential"}}},
				"2": {Format: "vc+sd-jwt", Vct: "SomeCredential"},
				"3": {Format: "vc+sd-jwt", Vct: "SomeCredential"},
			},
		}

		_, err := metadata.ResolveCredentialConfigurationID("SomeCredential")

		assert.EqualError(t, err, `issuer offers "SomeCredential" only in format(s): mso_mdoc, vc+sd-jwt`)
	})
	t.Run("error - rejects the base VerifiableCredential type upfront", func(t *testing.T) {
		metadata := OpenIDCredentialIssuerMetadata{
			CredentialConfigurationsSupported: map[string]CredentialConfiguration{
				"UniversityDegreeCredential_jwt_vc_json": {
					Format:               "jwt_vc_json",
					CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
				},
			},
		}

		// Every credential_definition.type array contains "VerifiableCredential"; without this
		// guard it would resolve to an arbitrary, unrelated credential_configuration_id.
		_, err := metadata.ResolveCredentialConfigurationID("VerifiableCredential")

		assert.EqualError(t, err, `issuer does not offer a credential of type "VerifiableCredential"`)
	})
}

func TestCredentialConfiguration_MatchesType(t *testing.T) {
	t.Run("matches credential_definition.type", func(t *testing.T) {
		config := CredentialConfiguration{
			Format:               "jwt_vc_json",
			CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}},
		}

		assert.True(t, config.MatchesType("UniversityDegreeCredential"))
		assert.False(t, config.MatchesType("OtherCredential"))
	})
	t.Run("matches the base VerifiableCredential type like any other entry", func(t *testing.T) {
		// Excluding "VerifiableCredential" as a resolvable type is the caller's
		// responsibility (see ResolveCredentialConfigurationID); MatchesType itself does a
		// plain membership check.
		config := CredentialConfiguration{
			Format:               "jwt_vc_json",
			CredentialDefinition: &CredentialDefinition{Type: []string{"VerifiableCredential"}},
		}

		assert.True(t, config.MatchesType("VerifiableCredential"))
	})
	t.Run("matches vct", func(t *testing.T) {
		config := CredentialConfiguration{Format: "vc+sd-jwt", Vct: "UniversityDegreeCredential"}

		assert.True(t, config.MatchesType("UniversityDegreeCredential"))
		assert.False(t, config.MatchesType("OtherCredential"))
	})
	t.Run("no credential_definition and no vct", func(t *testing.T) {
		config := CredentialConfiguration{Format: "jwt_vc_json"}

		assert.False(t, config.MatchesType("UniversityDegreeCredential"))
	})
}
