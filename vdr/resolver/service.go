/*
 * Copyright (C) 2023 Nuts community
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

package resolver

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"strings"
)

// ErrDuplicateService is returned when a DID Document contains a multiple services with the same type
var ErrDuplicateService = errors.New("service type is duplicate")

// ErrServiceNotFound is returned when the service is not found on a DID
var ErrServiceNotFound = errors.New("service not found in DID Document")

// ErrServiceReferenceToDeep is returned when a service reference is chain is nested too deeply.
var ErrServiceReferenceToDeep = errors.New("service references are nested to deeply before resolving to a non-reference")

// ServiceResolver allows looking up DID document services, following references.
type ServiceResolver interface {
	// Resolve looks up the DID document of the specified query and then tries to find the service with the specified type.
	// The query must be in the form of a service query, e.g. `did:nuts:12345/serviceEndpoint?type=some-type`.
	// The maxDepth indicates how deep references are followed. If maxDepth = 0, no references are followed (and an error is returned if the given query resolves to a reference).
	// If the DID document or service is not found, a reference can't be resolved or the references exceed maxDepth, an error is returned.
	Resolve(query ssi.URI, maxDepth int) (did.Service, error)

	// ResolveEx tries to resolve a DID service from the given endpoint URI, following references (URIs that begin with 'did:').
	// When the endpoint is a reference it resolves it up until the (per spec) max reference depth. When resolving a reference it recursively calls itself with depth + 1.
	// The documentCache map is used to avoid resolving the same document over and over again, which might be a (slightly more) expensive operation.
	ResolveEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error)
}

// DefaultMaxServiceReferenceDepth holds the default max. allowed depth for DID service references.
const DefaultMaxServiceReferenceDepth = 5

// DIDServiceResolver is a wrapper around a DID store that allows resolving services, following references.
type DIDServiceResolver struct {
	Resolver DIDResolver
}

func (s DIDServiceResolver) Resolve(query ssi.URI, maxDepth int) (did.Service, error) {
	return s.ResolveEx(query, 0, maxDepth, map[string]*did.Document{})
}

func (s DIDServiceResolver) ResolveEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error) {
	if depth >= maxDepth {
		return did.Service{}, ErrServiceReferenceToDeep
	}

	referencedDID, err := GetDIDFromURL(endpoint.String())
	if err != nil {
		// Shouldn't happen, because only DID URLs are passed?
		return did.Service{}, err
	}
	var document *did.Document
	if document = documentCache[referencedDID.String()]; document == nil {
		document, _, err = s.Resolver.Resolve(referencedDID, nil)
		if err != nil {
			return did.Service{}, err
		}
		documentCache[referencedDID.String()] = document
	}

	var service *did.Service
	for _, curr := range document.Service {
		if curr.Type == endpoint.Query().Get(serviceTypeQueryParameter) {
			// If there are multiple services with the same type the document is conflicted.
			// This can happen temporarily during a service update (delete old, add new).
			// Both endpoints are likely to be active in the timeframe that the conflict exists, so picking the first entry is preferred for availability over an error.
			service = &curr
			break
		}
	}
	if service == nil {
		return did.Service{}, ErrServiceNotFound
	}

	var endpointURL string
	if service.UnmarshalServiceEndpoint(&endpointURL) == nil {
		// Service endpoint is a string, if it's a reference we need to resolve it
		if IsServiceReference(endpointURL) {
			// Looks like a reference, recurse
			resolvedEndpointURI, err := ssi.ParseURI(endpointURL)
			if err != nil {
				return did.Service{}, err
			}
			err = ValidateServiceReference(*resolvedEndpointURI)
			if err != nil {
				return did.Service{}, err
			}
			return s.ResolveEx(*resolvedEndpointURI, depth+1, maxDepth, documentCache)
		}
	}
	return *service, nil
}

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

// ServiceQueryError denies the query based on validation constraints.
type ServiceQueryError struct {
	Err error // cause
}

// Error implements the error interface.
func (e ServiceQueryError) Error() string {
	return "DID service query invalid: " + e.Err.Error()
}

// Unwrap implements the errors.Unwrap convention.
func (e ServiceQueryError) Unwrap() error { return e.Err }

// ValidateServiceReference checks whether the given URI matches the format for a service reference.
func ValidateServiceReference(endpointURI ssi.URI) error {
	// Parse it as DID URL since DID URLs are rootless and thus opaque (RFC 3986), meaning the path will be part of the URI body, rather than the URI path.
	// For DID URLs the path is parsed properly.
	didEndpointURL, err := did.ParseDIDURL(endpointURI.String())
	if err != nil {
		return ServiceQueryError{err}
	}

	if "/"+didEndpointURL.Path != serviceEndpointPath {
		return ServiceQueryError{errors.New("endpoint URI path must be " + serviceEndpointPath)}
	}

	q := endpointURI.Query()
	switch len(q[serviceTypeQueryParameter]) {
	case 1:
		break // good
	case 0:
		return ServiceQueryError{errors.New("endpoint URI without " + serviceTypeQueryParameter + " query parameter")}
	default:
		return ServiceQueryError{errors.New("endpoint URI with multiple " + serviceTypeQueryParameter + " query parameters")}
	}

	// “Other query parameters, paths or fragments SHALL NOT be used.”
	// — RFC006, subsection 4.2
	if len(q) > 1 {
		return ServiceQueryError{errors.New("endpoint URI with query parameter other than " + serviceTypeQueryParameter)}
	}

	return nil
}
