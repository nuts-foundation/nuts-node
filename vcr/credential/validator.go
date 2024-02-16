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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/statuslist"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/piprate/json-gold/ld"
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

// AllFieldsDefinedValidator is a Validator that tests whether all fields are defined in the JSON-LD context.
type AllFieldsDefinedValidator struct {
	DocumentLoader ld.DocumentLoader
}

// Validate implements Validator.Validate.
func (d AllFieldsDefinedValidator) Validate(input vc.VerifiableCredential) error {
	// Expand with safe mode enabled, which asserts that all properties are defined in the JSON-LD context.
	inputAsJSON, _ := input.MarshalJSON()
	document, err := ld.DocumentFromReader(bytes.NewReader(inputAsJSON))
	if err != nil {
		return err
	}

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = d.DocumentLoader
	options.SafeMode = true

	if _, err = processor.Expand(document, options); err != nil {
		return &validationError{msg: err.Error()}
	}
	return nil
}

type defaultCredentialValidator struct {
}

func (d defaultCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if !credential.IsType(vc.VerifiableCredentialTypeV1URI()) {
		return failure("type 'VerifiableCredential' is required")
	}

	if !credential.ContainsContext(vc.VCContextV1URI()) {
		return failure("default context is required")
	}

	if credential.ID == nil {
		return failure("'ID' is required")
	}

	// 'issuanceDate' must be present, but can be zero if replaced by alias 'validFrom'
	if (credential.IssuanceDate == nil || credential.IssuanceDate.IsZero()) &&
		(credential.ValidFrom == nil || credential.ValidFrom.IsZero()) {
		return failure("'issuanceDate' is required")
	}

	if credential.Format() == vc.JSONLDCredentialProofFormat && credential.Proof == nil {
		return failure("'proof' is required for JSON-LD credentials")
	}

	// CredentialStatus is not specific to the credential type and the syntax (not status) should be checked here.
	if err := validateCredentialStatus(credential); err != nil {
		return failure("invalid credentialStatus: %s", err)
	}

	return nil
}

// validateCredentialStatus validates the
func validateCredentialStatus(credential vc.VerifiableCredential) error {
	// exit if the credential does not contain a status
	if credential.CredentialStatus == nil {
		return nil
	}

	// get base form of all credentialStatus
	statuses, err := credential.CredentialStatuses()
	if err != nil {
		return err
	}

	// validate per CredentialStatus.Type
	for _, credentialStatus := range statuses {
		// base requirements
		if credentialStatus.ID.String() == "" {
			return errors.New("credentialStatus.id is required")
		}
		if credentialStatus.Type == "" {
			return errors.New("credentialStatus.type is required")
		}

		// only accept StatusList2021EntryType for now
		if credentialStatus.Type != statuslist.StatusList2021EntryType {
			continue
		}
		// TODO: AllFieldsDefined validator should be sufficient?

		if !credential.ContainsContext(statuslist.StatusList2021ContextURI) {
			return errors.New("StatusList2021 context is required")
		}

		// unmarshal as StatusList2021Entry
		var cs statuslist.StatusList2021Entry
		if err = json.Unmarshal(credentialStatus.Raw(), &cs); err != nil {
			return err
		}

		// 'id' MUST NOT be the URL for the status list
		if cs.ID == cs.StatusListCredential {
			return errors.New("StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
		}

		// StatusPurpose must contain a purpose
		if cs.StatusPurpose == "" {
			return errors.New("StatusList2021Entry.statusPurpose is required")
		}

		// statusListIndex must be a non-negative number
		if n, err := strconv.Atoi(cs.StatusListIndex); err != nil || n < 0 {
			return errors.New("invalid StatusList2021Entry.statusListIndex")
		}

		// 'statusListCredential' must be a URL
		if _, err = url.ParseRequestURI(cs.StatusListCredential); err != nil {
			return fmt.Errorf("parse StatusList2021Entry.statusListCredential URL: %w", err)
		}
	}

	// valid
	return nil
}

// nutsOrganizationCredentialValidator checks if there's a 'name' and 'city' in the 'organization' struct
type nutsOrganizationCredentialValidator struct {
}

func (d nutsOrganizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsOrganizationCredentialSubject, 0)

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsOrganizationCredentialTypeURI) {
		return failure("type '%s' is required", NutsOrganizationCredentialType)
	}

	if !credential.ContainsContext(NutsV1ContextURI) {
		return failure("context '%s' is required", NutsV1ContextURI.String())
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
	if _, err = did.ParseDID(cs.ID); err != nil {
		return failure("invalid 'credentialSubject.id': %v", err)
	}

	if n, ok := cs.Organization["name"]; !ok || len(strings.TrimSpace(n)) == 0 {
		return failure("'credentialSubject.name' is empty")
	}

	if c, ok := cs.Organization["city"]; !ok || len(strings.TrimSpace(c)) == 0 {
		return failure("'credentialSubject.city' is empty")
	}

	return (defaultCredentialValidator{}).Validate(credential)
}

// nutsAuthorizationCredentialValidator checks for mandatory fields: id, purposeOfUse.
// Also checks whether the specified resources
type nutsAuthorizationCredentialValidator struct {
}

func (d nutsAuthorizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsAuthorizationCredentialSubject, 0)

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsAuthorizationCredentialTypeURI) {
		return failure("type '%s' is required", NutsAuthorizationCredentialType)
	}

	if !credential.ContainsContext(NutsV1ContextURI) {
		return failure("context '%s' is required", NutsV1ContextURI.String())
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
	if _, err = did.ParseDID(cs.ID); err != nil {
		return failure("invalid 'credentialSubject.id': %v", err)
	}
	if len(strings.TrimSpace(cs.PurposeOfUse)) == 0 {
		return failure("'credentialSubject.PurposeOfUse' is nil")
	}

	err = validateResources(cs.Resources)
	if err != nil {
		return err
	}

	return (defaultCredentialValidator{}).Validate(credential)
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
	id, err := resolver.GetDIDFromURL(credential.ID.String())
	if err != nil {
		return err
	}
	if id.String() != credential.Issuer.String() {
		return failure("credential ID must start with issuer")
	}
	return nil
}
