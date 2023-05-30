/*
 * Copyright (C) 2022 Nuts community
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
 */

package didservice

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

const serviceTypeQueryParameter = "type"
const serviceEndpointPath = "/serviceEndpoint"

// MakeServiceReference creates a service reference, which can be used as query when looking up services.
func MakeServiceReference(subjectDID did.DID, serviceType string) ssi.URI {
	ref := subjectDID.URI()
	ref.Opaque += serviceEndpointPath
	ref.Fragment = ""
	ref.RawQuery = fmt.Sprintf("%s=%s", serviceTypeQueryParameter, serviceType)
	return ref
}

// IsServiceReference checks whether the given endpoint string looks like a service reference (e.g. did:nuts:1234/serviceType?type=HelloWorld).
func IsServiceReference(endpoint string) bool {
	return strings.HasPrefix(endpoint, "did:")
}

// GetDIDFromURL returns the DID from the given URL, stripping any query parameters, path segments and fragments.
func GetDIDFromURL(didURL string) (did.DID, error) {
	parsed, err := did.ParseDIDURL(didURL)
	if err != nil {
		return did.DID{}, err
	}
	parsed.Fragment = ""
	parsed.Query = ""
	parsed.Path = ""
	parsed.Params = nil
	parsed.PathSegments = nil
	return *parsed, nil
}

// DIDServiceQueryError denies the query based on validation constraints.
type DIDServiceQueryError struct {
	Err error // cause
}

// Error implements the error interface.
func (e DIDServiceQueryError) Error() string {
	return "DID service query invalid: " + e.Err.Error()
}

// Unwrap implements the errors.Unwrap convention.
func (e DIDServiceQueryError) Unwrap() error { return e.Err }

// ValidateServiceReference checks whether the given URI matches the format for a service reference.
func ValidateServiceReference(endpointURI ssi.URI) error {
	// Parse it as DID URL since DID URLs are rootless and thus opaque (RFC 3986), meaning the path will be part of the URI body, rather than the URI path.
	// For DID URLs the path is parsed properly.
	didEndpointURL, err := did.ParseDIDURL(endpointURI.String())
	if err != nil {
		return DIDServiceQueryError{err}
	}

	if "/"+didEndpointURL.Path != serviceEndpointPath {
		return DIDServiceQueryError{errors.New("endpoint URI path must be " + serviceEndpointPath)}
	}

	q := endpointURI.Query()
	switch len(q[serviceTypeQueryParameter]) {
	case 1:
		break // good
	case 0:
		return DIDServiceQueryError{errors.New("endpoint URI without " + serviceTypeQueryParameter + " query parameter")}
	default:
		return DIDServiceQueryError{errors.New("endpoint URI with multiple " + serviceTypeQueryParameter + " query parameters")}
	}

	// “Other query parameters, paths or fragments SHALL NOT be used.”
	// — RFC006, subsection 4.2
	if len(q) > 1 {
		return DIDServiceQueryError{errors.New("endpoint URI with query parameter other than " + serviceTypeQueryParameter)}
	}

	return nil
}

// IsDeactivated returns true if the DID.Document has already been deactivated
func IsDeactivated(document did.Document) bool {
	return len(document.Controller) == 0 && len(document.CapabilityInvocation) == 0
}
