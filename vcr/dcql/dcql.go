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

// Package dcql implements a subset of the Digital Credentials Query Language (DCQL)
// as specified in OpenID4VP sections 6.1, 6.3, and 7.
//
// # Supported DCQL features
//
// Credential Query (section 6.1):
//   - id: validated per spec (non-empty, alphanumeric/underscore/hyphen)
//   - claims: array of claims queries
//
// Claims Query (section 6.3):
//   - path: Claims Path Pointer per section 7 (strings, integers, null)
//   - values: exact value matching with OR semantics
//
// Claims Path Pointer (section 7):
//   - String elements: key lookup in JSON objects
//   - Non-negative integer elements: array index lookup
//   - Null elements: wildcard, selects all elements of an array
//   - Path starts at the credential root
//
// # Unsupported features
//
// The following Credential Query fields are not supported as they are handled
// by other layers (PD matching, VP verification, filter chain):
// format, meta, multiple, claim_sets, trusted_authorities, require_cryptographic_holder_binding.
package dcql

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/nuts-foundation/go-did/vc"
)

var validIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// CredentialQuery represents a DCQL credential query as defined in OpenID4VP section 6.1.
type CredentialQuery struct {
	// ID is an identifier for the credential query. When used with PD matching,
	// this maps to a PD input descriptor ID.
	ID string `json:"id"`
	// Claims specifies the claim requirements for matching credentials.
	Claims []ClaimsQuery `json:"claims"`
}

// ClaimsQuery represents a DCQL claims query as defined in OpenID4VP section 6.3.
type ClaimsQuery struct {
	// Path is a Claims Path Pointer (OpenID4VP section 7) specifying the path to a claim
	// within the credential. Elements can be strings (key lookup), non-negative integers
	// (array index), or nil (array wildcard).
	Path []any `json:"path"`
	// Values specifies the expected values of the claim. If present, the credential
	// matches only if the claim value equals at least one of the values (OR semantics).
	Values []any `json:"values,omitempty"`
}

// Match evaluates a DCQL credential query against a list of verifiable credentials
// and returns the credentials that match all claims in the query.
// Returns an error if the query is invalid (e.g., invalid ID format).
func Match(query CredentialQuery, credentials []vc.VerifiableCredential) ([]vc.VerifiableCredential, error) {
	if err := validateQuery(query); err != nil {
		return nil, err
	}
	var result []vc.VerifiableCredential
	for _, cred := range credentials {
		if matchesAll(query.Claims, cred) {
			result = append(result, cred)
		}
	}
	return result, nil
}

func validateQuery(query CredentialQuery) error {
	if query.ID == "" {
		return fmt.Errorf("invalid credential query id: must be a non-empty string")
	}
	if !validIDPattern.MatchString(query.ID) {
		return fmt.Errorf("invalid credential query id: must consist of alphanumeric, underscore, or hyphen characters")
	}
	return nil
}

func matchesAll(claims []ClaimsQuery, cred vc.VerifiableCredential) bool {
	for _, claim := range claims {
		if !matchesClaim(claim, cred) {
			return false
		}
	}
	return true
}

func matchesClaim(claim ClaimsQuery, cred vc.VerifiableCredential) bool {
	value := resolvePath(claim.Path, cred)
	if value == nil {
		return false
	}
	if len(claim.Values) == 0 {
		return true
	}
	for _, expected := range claim.Values {
		if value == expected {
			return true
		}
	}
	return false
}

// resolvePath resolves a Claims Path Pointer (OpenID4VP section 7) against a credential.
// The path starts at the credential root. Returns nil if the path cannot be resolved.
// credentialSubject is treated as a single object (the first element of the array),
// since in practice it always contains exactly one entry.
func resolvePath(path []any, cred vc.VerifiableCredential) any {
	if len(path) == 0 {
		return nil
	}
	// Marshal credential to a generic JSON map so we can walk it from the root
	data, err := json.Marshal(cred)
	if err != nil {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	// Unwrap credentialSubject from array to single object for ergonomic path access.
	// The VC data model defines credentialSubject as an array, but in practice it always
	// contains exactly one entry. This allows paths like ["credentialSubject", "patientId"]
	// instead of ["credentialSubject", 0, "patientId"].
	if cs, ok := root["credentialSubject"]; ok {
		if arr, ok := cs.([]any); ok && len(arr) == 1 {
			root["credentialSubject"] = arr[0]
		}
	}
	return resolveInValue(path, root)
}

// resolveInValue resolves a Claims Path Pointer (OpenID4VP section 7) against a JSON value.
// Path elements can be: string (object key lookup), float64/int (array index), or nil (array wildcard).
func resolveInValue(path []any, value any) any {
	if len(path) == 0 {
		return value
	}
	switch element := path[0].(type) {
	case string:
		m, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		child, ok := m[element]
		if !ok {
			return nil
		}
		return resolveInValue(path[1:], child)
	case int:
		return resolveArrayIndex(path[1:], value, element)
	case float64:
		// JSON unmarshalling produces float64 for numbers
		return resolveArrayIndex(path[1:], value, int(element))
	default:
		return nil
	}
}

func resolveArrayIndex(remainingPath []any, value any, index int) any {
	arr, ok := value.([]any)
	if !ok {
		return nil
	}
	if index < 0 || index >= len(arr) {
		return nil
	}
	return resolveInValue(remainingPath, arr[index])
}
