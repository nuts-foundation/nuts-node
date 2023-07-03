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
	"errors"
	"github.com/nuts-foundation/go-did/vc"
)

func CredentialDefinitionDescribesCredential(credential vc.VerifiableCredential, credentialDefinition map[string]interface{}) error {
	// check context
	definitionContexts, ok := credentialDefinition["@context"].([]interface{})
	if !ok {
		return errors.New("missing '@context' in credential_definition")
	}
	// credential may contain more contexts than the definition if it already contains signature or proof contexts.
	if len(definitionContexts) > len(credential.Context) {
		return errors.New("@context do not match")
	}
	for _, defContext := range definitionContexts {
		found := false
		for _, vcContext := range credential.Context {
			if defContext == vcContext.String() {
				found = true
				break
			}
		}
		if !found {
			return errors.New("@context do not match")
		}
	}

	// check type
	definitionTypes, ok := credentialDefinition["type"].([]interface{})
	if !ok {
		return errors.New("missing 'type' in credential_definition")
	}
	if len(credential.Type) != len(definitionTypes) {
		return errors.New("type do not match")
	}
	for _, defType := range definitionTypes {
		found := false
		for _, vcType := range credential.Type {
			if defType == vcType.String() {
				found = true
				break
			}
		}
		if !found {
			return errors.New("type do not match")
		}
	}

	return nil
}
