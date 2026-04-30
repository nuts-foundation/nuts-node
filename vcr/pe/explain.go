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

package pe

import (
	"encoding/json"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
)

// credentialID returns the credential's id as a string, or "" if the credential has no id.
func credentialID(credential vc.VerifiableCredential) string {
	if credential.ID == nil {
		return ""
	}
	return credential.ID.String()
}

// credentialToMap unmarshals a credential to a generic map, regardless of its on-the-wire format.
// Mirrors the conversion done in matchConstraint.
func credentialToMap(credential vc.VerifiableCredential) (map[string]interface{}, error) {
	switch credential.Format() {
	case vc.JWTCredentialProofFormat:
		type Alias vc.VerifiableCredential
		return remarshalToMap(Alias(credential))
	default:
		return remarshalToMap(credential)
	}
}

// explainConstraintMismatch returns a human-readable reason why the given constraint does
// not match the given credential. It assumes the constraint has already been determined
// not to match. Returns a generic message if no individual field rejects (which would be a bug).
func explainConstraintMismatch(constraint *Constraints, credentialAsMap map[string]interface{}) string {
	for _, field := range constraint.Fields {
		if reason := explainFieldMismatch(field, credentialAsMap); reason != "" {
			return reason
		}
	}
	return "no individual field rejected the credential"
}

// explainFieldMismatch returns a human-readable reason why the given field does not match
// the credential, or "" if the field does match.
func explainFieldMismatch(field Field, credential map[string]interface{}) string {
	var lastFoundPath string
	var lastFoundValue interface{}
	var optionalInvalid int
	for _, path := range field.Path {
		value, err := getValueAtPath(path, credential)
		if err != nil {
			return fmt.Sprintf("%spath %q: %s", fieldLabel(field), path, err.Error())
		}
		if value == nil {
			continue
		}
		if field.Filter == nil {
			return ""
		}
		match, _, err := matchFilter(*field.Filter, value)
		if err != nil {
			return fmt.Sprintf("%spath %q value %v: %s", fieldLabel(field), path, value, err.Error())
		}
		if match {
			return ""
		}
		lastFoundPath = path
		lastFoundValue = value
		optionalInvalid++
	}
	if field.Optional != nil && *field.Optional && optionalInvalid == 0 {
		return ""
	}
	if optionalInvalid > 0 {
		filterDesc, _ := json.Marshal(field.Filter)
		return fmt.Sprintf("%spath %q found value %v which did not match filter %s", fieldLabel(field), lastFoundPath, lastFoundValue, filterDesc)
	}
	return fmt.Sprintf("%sno value found at any of paths %v", fieldLabel(field), field.Path)
}

func fieldLabel(field Field) string {
	if field.Id != nil {
		return fmt.Sprintf("field %q ", *field.Id)
	}
	return ""
}
