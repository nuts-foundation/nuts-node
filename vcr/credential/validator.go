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
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/piprate/json-gold/ld"
	"reflect"
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

type defaultCredentialValidator struct {
	documentLoader ld.DocumentLoader
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

	if credential.IssuanceDate.IsZero() {
		return failure("'issuanceDate' is required")
	}

	if credential.Proof == nil {
		return failure("'proof' is required")
	}

	return d.validateAllFieldsKnown(credential)
}

// validateAllFieldsKnown verifies that all fields in the VC are specified by the JSON-LD context.
func (d defaultCredentialValidator) validateAllFieldsKnown(input vc.VerifiableCredential) error {
	// First expand, then compact and marshal to JSON, then compare
	inputAsJSON, _ := input.MarshalJSON()
	inputAsMap := make(map[string]interface{})
	_ = json.Unmarshal(inputAsJSON, &inputAsMap)
	normalizeJSONLDVC(inputAsMap)
	expectedAsJSON, _ := json.Marshal(inputAsMap)

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = d.documentLoader
	compactedAsMap, err := processor.Compact(inputAsMap, inputAsMap, options)
	if err != nil {
		return failure("unable to compact JSON-LD VC: %s", err)
	}
	normalizeJSONLDVC(compactedAsMap)
	compactedAsJSON, _ := json.Marshal(compactedAsMap)

	if string(expectedAsJSON) != string(compactedAsJSON) {
		log.Logger().Debug("VC validation failed, not all fields are defined by JSON-LD context")
		log.Logger().Debugf(" Given VC:      %s", string(expectedAsJSON))
		log.Logger().Debugf(" Cleaned up VC: %s", string(compactedAsJSON))
		return failure("not all fields are defined by JSON-LD context")
	}
	return nil
}

// nutsOrganizationCredentialValidator checks if there's a 'name' and 'city' in the 'organization' struct
type nutsOrganizationCredentialValidator struct {
	documentLoader ld.DocumentLoader
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

	if n, ok := cs.Organization["name"]; !ok || len(strings.TrimSpace(n)) == 0 {
		return failure("'credentialSubject.name' is empty")
	}

	if c, ok := cs.Organization["city"]; !ok || len(strings.TrimSpace(c)) == 0 {
		return failure("'credentialSubject.city' is empty")
	}

	return (defaultCredentialValidator{d.documentLoader}).Validate(credential)
}

// nutsAuthorizationCredentialValidator checks for mandatory fields: id, purposeOfUse.
// Also checks whether the specified resources
type nutsAuthorizationCredentialValidator struct {
	documentLoader ld.DocumentLoader
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
	if len(strings.TrimSpace(cs.PurposeOfUse)) == 0 {
		return failure("'credentialSubject.PurposeOfUse' is nil")
	}

	err = validateResources(cs.Resources)
	if err != nil {
		return err
	}

	return (defaultCredentialValidator{d.documentLoader}).Validate(credential)
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
	var idWithoutFragment ssi.URI
	if credential.ID != nil {
		idWithoutFragment = *credential.ID
		idWithoutFragment.Fragment = ""
	}
	if idWithoutFragment.String() != credential.Issuer.String() {
		return failure("credential ID must start with issuer")
	}
	return nil
}

// normalizeJSONLDVC takes a JSON-LD Verifiable Credential unmarshaled into a map and normalizes it, to structure it the same JSON-LD compaction would do.
// This is used for validating whether JSON-LD stays the same after compaction (for checking whether all fields are defined in the context).
// The following changes are made by normalizing:
// - Slices with 1 entry are "unsliced", so it becomes a scalar value
// - Empty map entries are removed
func normalizeJSONLDVC(input map[string]interface{}) {
	delete(input, "proof")
	normalizeJSONMap(input)
}

// normalizeJSONMap see normalizeJSONLDVC
func normalizeJSONMap(input map[string]interface{}) {
	for key, v := range input {
		if v == nil {
			// Remove empty properties
			delete(input, key)
			continue
		}
		normalizeJSONProperty(v, func(newValue interface{}) {
			input[key] = newValue
		})
	}
}

// normalizeJSONProperty see normalizeJSONLDVC
func normalizeJSONProperty(input interface{}, setter func(newValue interface{})) {
	value := reflect.ValueOf(input)
	// If it's a slice with a single value, unslice it
	if value.Kind() == reflect.Slice {
		switch value.Len() {
		case 0:
			// Empty slice, do nothing
		case 1:
			// Slice with 1 entry, unslice it
			input = value.Index(0).Interface()
			setter(input)
		default:
			// Slice with zero or more entries, iterate
			normalizeJSONSlice(value)
		}
	}

	asMap, isMap := input.(map[string]interface{})
	if isMap {
		if idValue, hasID := asMap["id"]; hasID && len(asMap) == 1 {
			setter(idValue)
		} else {
			normalizeJSONMap(asMap)
		}
	}
}

// normalizeJSONSlice see normalizeJSONLDVC
func normalizeJSONSlice(input reflect.Value) {
	length := input.Len()
	for i := 0; i < length; i++ {
		current := input.Index(i)
		normalizeJSONProperty(current, func(newValue interface{}) {
			current.Set(reflect.ValueOf(newValue))
		})
	}
}
