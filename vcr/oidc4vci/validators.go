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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
)

// Validate the CredentialDefinition according to the VerifiableCredentialJSONLDFormat format
func (cd *CredentialDefinition) Validate(isOffer bool) error {
	if cd == nil {
		return errors.New("invalid credential_definition: missing")
	}
	if len(cd.Context) == 0 {
		return errors.New("invalid credential_definition: missing @context field")
	}
	if len(cd.Type) == 0 {
		return errors.New("invalid credential_definition: missing type field")
	}
	if cd.CredentialSubject != nil {
		if isOffer {
			return errors.New("invalid credential_definition: credentialSubject not allowed in offer")
		}
		// TODO: Add credentialSubject validation.
		//		 See https://github.com/nuts-foundation/nuts-node/issues/2320
	}
	return nil
}

// ValidateDefinitionWithCredential confirms that the vc.VerifiableCredential is defined by the CredentialDefinition.
// CredentialDefinition is assumed to be valid, see ValidateCredentialDefinition.
func ValidateDefinitionWithCredential(credential vc.VerifiableCredential, definition CredentialDefinition) error {
	// From spec: When the format value is ldp_vc, ..., including credential_definition object, MUST NOT be processed using JSON-LD rules.
	// https://openid.bitbucket.io/connect/editors-draft/openid-4-verifiable-credential-issuance-1_0.html#name-format-identifier-2

	// compare contexts. The credential may contain extra contexts for signatures or proofs
	if len(credential.Context) < len(definition.Context) || !isSubset(credential.Context, definition.Context) {
		return errors.New("credential does not match credential_definition: context mismatch")
	}

	// compare types. fails when definition.Type contains duplicates
	if len(credential.Type) != len(definition.Type) || !isSubset(credential.Type, definition.Type) {
		return errors.New("credential does not match credential_definition: type mismatch")
	}

	// TODO: Compare credentialSubject
	//		 See https://github.com/nuts-foundation/nuts-node/issues/2320

	return nil
}

// isSubset is true if all elements of subset exist in set. If subset is empty it returns false.
func isSubset(set, subset []ssi.URI) bool {
	if len(subset) == 0 {
		return false
	}
	for _, el1 := range subset {
		found := false
		for _, el2 := range set {
			if el2.String() == el1.String() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
