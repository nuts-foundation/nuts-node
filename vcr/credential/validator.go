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
	"time"

	"github.com/nuts-foundation/go-did"
)

// Validator is the interface specific VC verification.
// Every VC will have it's own rules of verification.
type Validator interface {
	// Validate the given credential according to the rules of the VC type.
	Validate(credential did.VerifiableCredential) error
}

// validate the default fields
func validate(credential did.VerifiableCredential) error {

	if !containsType(credential, DefaultCredentialType) {
		return errors.New("validation failed: 'VerifiableCredential' is required")
	}

	if !containsContext(credential, DefaultContext) {
		return errors.New("validation failed: default context is required")
	}

	if !containsContext(credential, NutsContext) {
		return errors.New("validation failed: nuts context is required")
	}

	if credential.ID == nil {
		return errors.New("validation failed: 'ID' is required")
	}

	if credential.IssuanceDate.Equal(time.Time{}) {
		return errors.New("validation failed: 'issuanceDate' is required")
	}

	if credential.Proof == nil {
		return errors.New("validation failed: 'proof' is required")
	}

	return nil
}

func containsType(credential did.VerifiableCredential, vcType string) bool {
	for _, t := range credential.Type {
		if t.String() == vcType {
			return true
		}
	}

	return false
}

func containsContext(credential did.VerifiableCredential, context string) bool {
	for _, c := range credential.Context {
		if c.String() == context {
			return true
		}
	}

	return false
}

// nutsOrganizationCredentialValidator checks if there's a 'name' and 'city' in the 'organization' struct
type nutsOrganizationCredentialValidator struct{}

func (d nutsOrganizationCredentialValidator) Validate(credential did.VerifiableCredential) error {
	var target = make([]NutsOrganizationCredentialSubject, 0)

	if err := validate(credential); err != nil {
		return err
	}

	if !containsType(credential, NutsOrganizationCredentialType) {
		return errors.New("validation failed: 'VerifiableCredential' is required")
	}

	// if it fails, length check will trigger
	_ = credential.UnmarshalCredentialSubject(&target)
	if len(target) != 1 {
		return errors.New("validation failed: single CredentialSubject expected")
	}
	cs := target[0]

	if cs.Organization == nil {
		return errors.New("validation failed: 'credentialSubject.organization' is empty")
	}
	if cs.ID == "" {
		return errors.New("validation failed: 'credentialSubject.ID' is nil")
	}

	if n, ok := cs.Organization["name"]; !ok || len(n) == 0 {
		return errors.New("validation failed: 'credentialSubject.name' is empty")
	}

	if c, ok := cs.Organization["city"]; !ok || len(c) == 0 {
		return errors.New("validation failed: 'credentialSubject.city' is empty")
	}

	return nil
}
