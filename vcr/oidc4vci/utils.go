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
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
)

// CredentialTypesMatchDefinition validates that credential matches VerifiableCredentialJSONLDFormat's credential_definition
func CredentialTypesMatchDefinition(reader jsonld.Reader, credential vc.VerifiableCredential, credentialDefinition map[string]interface{}) error {
	// In json-LD format the types need to be compared in expanded format
	document, err := reader.Read(credentialDefinition)
	if err != nil {
		return fmt.Errorf("invalid credential_definition: %w", err)
	}
	// TODO: can credentialDefinition contain invalid values that makes this panic?
	expectedTypes := document.ValueAt(jsonld.NewPath("@type"))

	document, err = reader.Read(credential)
	if err != nil {
		return fmt.Errorf("invalid credential: %w", err)
	}
	receivedTypes := document.ValueAt(jsonld.NewPath("@type"))

	if !equal(expectedTypes, receivedTypes) {
		return errors.New("credential Type do not match")
	}

	return nil
}

// equal returns true if both slices have the same values in the same order.
// Note: JSON arrays are ordered, JSON object elements are not.
func equal(a, b []jsonld.Scalar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
