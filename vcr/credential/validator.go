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
	"fmt"
	"strings"

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

	if !credential.IsType(did.VerifiableCredentialTypeV1URI()) {
		return errors.New("validation failed: 'VerifiableCredential' is required")
	}

	if !credential.ContainsContext(did.VCContextV1URI()) {
		return errors.New("validation failed: default context is required")
	}

	if !credential.ContainsContext(*NutsContextURI) {
		return errors.New("validation failed: nuts context is required")
	}

	if credential.ID == nil {
		return errors.New("validation failed: 'ID' is required")
	}

	if credential.IssuanceDate.IsZero() {
		return errors.New("validation failed: 'issuanceDate' is required")
	}

	if credential.Proof == nil {
		return errors.New("validation failed: 'proof' is required")
	}

	return nil
}

// ErrValidation is a common error indicating validation failed
var ErrValidation = errors.New("validation failed")

type validationError struct {
	msg string
}

// Error returns the error message
func (err *validationError) Error() string {
	return fmt.Sprintf("validation failed: %s", err.msg)
}

// Is checks if validationError matches the target error
func (err *validationError) Is(target error) bool {
	return errors.Is(target, ErrValidation)
}

func failure(err string) error {
	return &validationError{err}
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

	if !credential.IsType(*NutsOrganizationCredentialTypeURI) {
		return failure("'VerifiableCredential' is required")
	}

	// if it fails, length check will trigger
	_ = credential.UnmarshalCredentialSubject(&target)
	if len(target) != 1 {
		return failure("single CredentialSubject expected")
	}
	cs := target[0]

	if cs.Organization == nil {
		return failure("'credentialSubject.organization' is empty")
	}
	if cs.ID == "" {
		return failure("'credentialSubject.ID' is nil")
	}

	if n, ok := cs.Organization["name"]; !ok || len(strings.TrimSpace(n)) == 0 {
		return failure("'credentialSubject.name' is empty")
	}

	if c, ok := cs.Organization["city"]; !ok || len(strings.TrimSpace(c)) == 0 {
		return failure("'credentialSubject.city' is empty")
	}

	return nil
}
