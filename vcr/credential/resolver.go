/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package credential

import (
	"github.com/nuts-foundation/go-did"
)

// FindValidatorAndBuilder finds the Validator and Builder for the credential Type
// It returns nils when not found.
func FindValidatorAndBuilder(credential did.VerifiableCredential) (Validator, Builder) {
	if vcTypes := extractTypes(credential); len(vcTypes) > 0 {
		return defaultValidator{}, defaultBuilder{
			vcType: vcTypes[0],
		}
	}

	return nil, nil
}

func extractTypes(credential did.VerifiableCredential) []string {
	var vcTypes []string

	for _, t := range credential.Type {
		if "VerifiableCredential" != t.String() {
			vcTypes = append(vcTypes, t.String())
		}
	}

	return vcTypes
}
