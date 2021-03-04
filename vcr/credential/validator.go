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

	"github.com/nuts-foundation/go-did"
)

// Validator is the interface specific VC verification.
// Every VC will have it's own rules of verification.
type Validator interface{
	// Validate the given credential according to the rules of the VC type.
	Validate(credential did.VerifiableCredential) error
}

// validate the default fields
func validate(credential did.VerifiableCredential) error {
	return nil
}

// defaultValidator just checks if all fields in the credentialSubject have some sort of value.
// It doesn't detects missing fields.
type defaultValidator struct {}

func (d defaultValidator) Validate(credential did.VerifiableCredential) error {
	var target = make([]interface{}, 0)

	if err := validate(credential); err != nil {
		return err
	}

	if err := credential.UnmarshalCredentialSubject(&target); err != nil {
		return err
	}

	if !notEmptyRecursive(target) {
		return errors.New("validation failed: one or more fields are empty")
	}

	return nil
}

func notEmptyRecursive(val interface{}) bool {
	if m, ok := val.(map[string]interface{}); ok {
		if len(m) == 0 {
			return false
		}
		for _, v := range m {
			if b := notEmptyRecursive(v); !b {
				return false
			}
		}
	}

	if as, ok := val.([]interface{}); ok {
		if len(as) == 0 {
			return false
		}
		for _, a := range as {
			if b := notEmptyRecursive(a); !b {
				return false
			}
		}
	}

	if s, ok := val.(string); ok {
		return len(s) > 0
	}

	// numbers for example
	return true
}

