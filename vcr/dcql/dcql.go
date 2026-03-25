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
	"math"
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
// Returns an error if the query is invalid (e.g., invalid ID format) or if a credential
// cannot be processed.
// Returns an empty slice (not an error) when no credentials match.
func Match(query CredentialQuery, credentials []vc.VerifiableCredential) ([]vc.VerifiableCredential, error) {
	if err := validateQuery(query); err != nil {
		return nil, err
	}
	var result []vc.VerifiableCredential
	for _, cred := range credentials {
		root, err := credentialToMap(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to process credential: %w", err)
		}
		matched, err := matchesAll(query.Claims, root)
		if err != nil {
			return nil, err
		}
		if matched {
			result = append(result, cred)
		}
	}
	return result, nil
}

func validateQuery(query CredentialQuery) error {
	if !validIDPattern.MatchString(query.ID) {
		return fmt.Errorf("invalid credential query id: must be a non-empty string consisting of alphanumeric, underscore, or hyphen characters")
	}
	for i, claim := range query.Claims {
		if len(claim.Path) == 0 {
			return fmt.Errorf("claims[%d]: path must be a non-empty array", i)
		}
	}
	return nil
}

// credentialToMap converts a credential to a generic JSON map for path resolution.
// The Go VC struct models credentialSubject as []map[string]any, which marshals to a
// JSON array. The DCQL spec examples treat credentialSubject as a single object — paths
// use ["credentialSubject", "family_name"] without an array index (see OpenID4VP appendix D
// and section B.1.2). We unwrap single-element arrays to match this convention.
func credentialToMap(cred vc.VerifiableCredential) (map[string]any, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}
	if cs, ok := root["credentialSubject"]; ok {
		if arr, ok := cs.([]any); ok && len(arr) == 1 {
			root["credentialSubject"] = arr[0]
		}
	}
	return root, nil
}

func matchesAll(claims []ClaimsQuery, root map[string]any) (bool, error) {
	for _, claim := range claims {
		matched, err := matchesClaim(claim, root)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func matchesClaim(claim ClaimsQuery, root map[string]any) (bool, error) {
	resolved, err := resolveInValue(claim.Path, root)
	if err != nil {
		return false, err
	}
	if resolved == nil {
		return false, nil
	}
	if len(claim.Values) == 0 {
		return true, nil
	}
	return containsExpectedValue(resolved, claim.Values), nil
}

// containsExpectedValue checks whether the resolved value matches any of the expected values.
// If the value is a []any (from wildcard path resolution, possibly nested from multiple
// wildcards), it recursively searches all levels.
func containsExpectedValue(value any, expectedValues []any) bool {
	if slice, ok := value.([]any); ok {
		for _, elem := range slice {
			if containsExpectedValue(elem, expectedValues) {
				return true
			}
		}
		return false
	}
	for _, expected := range expectedValues {
		if value == expected {
			return true
		}
	}
	return false
}

// resolveInValue resolves a Claims Path Pointer (OpenID4VP section 7) against a JSON value.
// Path elements can be: string (object key lookup), float64/int (array index), or nil (array wildcard).
// Returns an error for invalid path elements (non-integer float, unsupported type).
func resolveInValue(path []any, value any) (any, error) {
	if len(path) == 0 {
		return value, nil
	}
	switch element := path[0].(type) {
	case string:
		m, ok := value.(map[string]any)
		if !ok {
			// If the value is an array with >1 elements and the path uses a string key,
			// the path is ambiguous — it needs an integer index to select an element.
			if arr, isArr := value.([]any); isArr && len(arr) > 1 {
				return nil, fmt.Errorf("path uses key '%s' on array with %d elements: use an integer index to select an element", element, len(arr))
			}
			return nil, nil
		}
		child, ok := m[element]
		if !ok {
			return nil, nil
		}
		return resolveInValue(path[1:], child)
	case int:
		if element < 0 {
			return nil, fmt.Errorf("invalid path element: %v is not a non-negative integer", element)
		}
		return resolveArrayIndex(path[1:], value, element)
	case float64:
		// JSON unmarshalling produces float64 for numbers. Validate it represents
		// a non-negative integer within int range before converting.
		if element < 0 || math.Trunc(element) != element || element > float64(math.MaxInt) {
			return nil, fmt.Errorf("invalid path element: %v is not a non-negative integer", element)
		}
		return resolveArrayIndex(path[1:], value, int(element))
	case nil:
		// Null wildcard: select all elements of the array
		arr, ok := value.([]any)
		if !ok {
			return nil, nil
		}
		if len(path) == 1 {
			return arr, nil
		}
		var results []any
		for _, item := range arr {
			resolved, err := resolveInValue(path[1:], item)
			if err != nil {
				return nil, err
			}
			if resolved != nil {
				results = append(results, resolved)
			}
		}
		if len(results) == 0 {
			return nil, nil
		}
		return results, nil
	default:
		return nil, fmt.Errorf("invalid path element type: %T", element)
	}
}

func resolveArrayIndex(remainingPath []any, value any, index int) (any, error) {
	arr, ok := value.([]any)
	if !ok {
		return nil, nil
	}
	if index < 0 || index >= len(arr) {
		return nil, nil
	}
	return resolveInValue(remainingPath, arr[index])
}
