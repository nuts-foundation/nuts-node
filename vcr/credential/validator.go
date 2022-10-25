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

	"github.com/nuts-foundation/go-did/vc"
)

// Validator is the interface specific VC verification.
// Every VC will have its own rules of verification.
type Validator interface {
	// Validate the given credential according to the rules of the VC type.
	Validate(credential vc.VerifiableCredential) error
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

func failure(err string, args ...interface{}) error {
	errStr := fmt.Sprintf(err, args...)
	return &validationError{errStr}
}

// Validate the default fields. This is credential type independent.
func Validate(credential vc.VerifiableCredential) error {
	if !credential.IsType(vc.VerifiableCredentialTypeV1URI()) {
		return failure("type 'VerifiableCredential' is required")
	}

	if !credential.ContainsContext(vc.VCContextV1URI()) {
		return failure("default context is required")
	}

	if credential.ID == nil {
		return failure("'ID' is required")
	}

	if credential.IssuanceDate.IsZero() {
		return failure("'issuanceDate' is required")
	}

	if credential.Proof == nil {
		return failure("'proof' is required")
	}

	return nil
}

type defaultCredentialValidator struct{}

func (d defaultCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if err := Validate(credential); err != nil {
		return err
	}
	return nil
}

// nutsOrganizationCredentialValidator checks if there's a 'name' and 'city' in the 'organization' struct
type nutsOrganizationCredentialValidator struct{}

func (d nutsOrganizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsOrganizationCredentialSubject, 0)

	if err := Validate(credential); err != nil {
		return err
	}

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsOrganizationCredentialTypeURI) {
		return failure("type '%s' is required", NutsOrganizationCredentialType)
	}

	if !credential.ContainsContext(*NutsContextURI) {
		return failure("context '%s' is required", NutsContextURI.String())
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

// nutsAuthorizationCredentialValidator checks for mandatory fields: id, purposeOfUse.
type nutsAuthorizationCredentialValidator struct{}

func (d nutsAuthorizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsAuthorizationCredentialSubject, 0)

	if err := Validate(credential); err != nil {
		return err
	}

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsAuthorizationCredentialTypeURI) {
		return failure("type '%s' is required", NutsAuthorizationCredentialType)
	}

	if !credential.ContainsContext(*NutsContextURI) {
		return failure("context '%s' is required", NutsContextURI.String())
	}

	// if it fails, length check will trigger
	_ = credential.UnmarshalCredentialSubject(&target)
	if len(target) != 1 {
		return failure("single CredentialSubject expected")
	}
	cs := target[0]

	if len(strings.TrimSpace(cs.ID)) == 0 {
		return failure("'credentialSubject.ID' is nil")
	}
	if len(strings.TrimSpace(cs.PurposeOfUse)) == 0 {
		return failure("'credentialSubject.PurposeOfUse' is nil")
	}
	return validateResources(cs.Resources)
}

func validOperationTypes() []string {
	return []string{"read", "vread", "update", "patch", "delete", "history", "create", "search", "document"}
}

func validateResources(resources []Resource) error {
	for _, r := range resources {
		if len(strings.TrimSpace(r.Path)) == 0 {
			return failure("'credentialSubject.Resources[].Path' is required'")
		}
		if len(r.Operations) == 0 {
			return failure("'credentialSubject.Resources[].Operations[]' requires at least one value")
		}
		for _, o := range r.Operations {
			if !validOperation(o) {
				return failure("'credentialSubject.Resources[].Operations[]' contains an invalid operation '%s'", o)
			}
		}
	}

	return nil
}

func validOperation(operation string) bool {
	for _, o := range validOperationTypes() {
		if o == strings.ToLower(operation) {
			return true
		}
	}
	return false
}

func validateNutsCredentialID(credential vc.VerifiableCredential) error {
	idWithoutFragment := *credential.ID
	idWithoutFragment.Fragment = ""
	if idWithoutFragment.String() != credential.Issuer.String() {
		return failure("credential ID must start with issuer")
	}
	return nil
}
