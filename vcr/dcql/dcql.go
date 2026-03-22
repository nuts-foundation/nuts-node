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
	// Path is a claims path pointer specifying the path to a claim within the credential.
	Path []string `json:"path"`
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
func resolvePath(path []string, cred vc.VerifiableCredential) any {
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
	return resolveInValue(path, root)
}

// resolveInValue resolves a path against an arbitrary JSON value.
func resolveInValue(path []string, value any) any {
	if len(path) == 0 {
		return value
	}
	switch v := value.(type) {
	case map[string]any:
		child, ok := v[path[0]]
		if !ok {
			return nil
		}
		return resolveInValue(path[1:], child)
	default:
		return nil
	}
}
