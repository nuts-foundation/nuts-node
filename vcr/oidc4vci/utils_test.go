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

package oidc4vci

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CredentialDefinitionDescribesCredential(t *testing.T) {
	credentialDefinition := map[string]any{
		"@context": []any{
			"a",
			"b",
		},
		"type": []any{"VerifiableCredential", "HumanCredential"},
	}
	credential := vc.VerifiableCredential{
		Context: []ssi.URI{ssi.MustParseURI("a"), ssi.MustParseURI("b")},
		Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("HumanCredential")},
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, CredentialDefinitionDescribesCredential(credential, credentialDefinition))
	})
	t.Run("error - credential_definition missing @context", func(t *testing.T) {
		err := CredentialDefinitionDescribesCredential(credential, map[string]interface{}{
			"type": []any{"VerifiableCredential", "HumanCredential"},
		})
		assert.EqualError(t, err, "missing '@context' in credential_definition")
	})
	t.Run("error - credential missing @context", func(t *testing.T) {
		err := CredentialDefinitionDescribesCredential(vc.VerifiableCredential{}, credentialDefinition)
		assert.EqualError(t, err, "@context do not match")
	})
	t.Run("error - credential_definition missing type", func(t *testing.T) {
		err := CredentialDefinitionDescribesCredential(credential, map[string]any{
			"@context": []any{"a", "b"},
		})
		assert.EqualError(t, err, "missing 'type' in credential_definition")
	})
	t.Run("error - types mismatch", func(t *testing.T) {
		err := CredentialDefinitionDescribesCredential(credential, map[string]any{
			"@context": []any{"a", "b"},
			"type":     []any{"VerifiableCredential", "NonHumanCredential"},
		})
		assert.EqualError(t, err, "type do not match")
	})
}
