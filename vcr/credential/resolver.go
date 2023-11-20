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
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
)

// FindValidator finds the Validator the provided credential based on its Type
// When no additional type is provided, it returns the default validator
func FindValidator(credential vc.VerifiableCredential) Validator {
	if vcTypes := ExtractTypes(credential); len(vcTypes) > 0 {
		for _, t := range vcTypes {
			switch t {
			case NutsOrganizationCredentialType:
				return nutsOrganizationCredentialValidator{}
			case NutsAuthorizationCredentialType:
				return nutsAuthorizationCredentialValidator{}
			}
		}
	}
	return defaultCredentialValidator{}
}

// ExtractTypes extract additional VC types from the VC as strings
// It removes the default `VerifiableCredential` type from the types, returns the rest.
func ExtractTypes(credential vc.VerifiableCredential) []string {
	var vcTypes []string

	for _, t := range credential.Type {
		if t != vc.VerifiableCredentialTypeV1URI() {
			vcTypes = append(vcTypes, t.String())
		}
	}

	return vcTypes
}

func PresentationSigner(presentation vc.VerifiablePresentation) (*did.DID, error) {
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		token := presentation.JWT()
		issuer := token.Issuer()
		if issuer == "" {
			return nil, errors.New("JWT presentation does not have 'iss' claim")
		}
		return did.ParseDID(issuer)
	default:
		return nil, errors.New("unsupported presentation format")
	}
}
