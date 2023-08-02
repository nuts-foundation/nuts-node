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

// Package service contains DID Document related functionality that only matters to the current node.
// All functionality here has zero relations to the network.
package didservice

import (
	"crypto"
	"errors"
	"fmt"
	"sync"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DefaultMaxServiceReferenceDepth holds the default max. allowed depth for DID service references.
const DefaultMaxServiceReferenceDepth = 5

var _ types.DIDResolver = &DIDResolverRouter{}

// DIDResolverRouter is a DID resolver that can route to different DID resolvers based on the DID method
type DIDResolverRouter struct {
	resolvers sync.Map
}

// Resolve looks up the right resolver for the given DID and delegates the resolution to it.
// If no resolver is registered for the given DID method, ErrDIDMethodNotSupported is returned.
func (r *DIDResolverRouter) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	method := id.Method
	resolver, registered := r.resolvers.Load(method)
	if !registered {
		return nil, nil, types.ErrDIDMethodNotSupported
	}
	return resolver.(types.DIDResolver).Resolve(id, metadata)
}

// Register registers a DID resolver for the given DID method.
func (r *DIDResolverRouter) Register(method string, resolver types.DIDResolver) {
	r.resolvers.Store(method, resolver)
}

var _ types.KeyResolver = KeyResolver{}

// KeyResolver implements the KeyResolver interface that uses keys from resolved DIDs.
type KeyResolver struct {
	Resolver types.DIDResolver
}

func (r KeyResolver) ResolveKeyByID(keyID string, validAt *time.Time, relationType types.RelationType) (crypto.PublicKey, error) {
	holder, err := GetDIDFromURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	doc, _, err := r.Resolver.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return nil, err
	}
	relationships, err := resolveRelationships(doc, relationType)
	if err != nil {
		return nil, err
	}
	for _, rel := range relationships {
		if rel.ID.String() == keyID {
			return rel.PublicKey()
		}
	}
	return nil, types.ErrKeyNotFound
}

func (r KeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType types.RelationType) (ssi.URI, crypto.PublicKey, error) {
	doc, _, err := r.Resolver.Resolve(id, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return ssi.URI{}, nil, err
	}
	keys, err := resolveRelationships(doc, relationType)
	if err != nil {
		return ssi.URI{}, nil, err
	}
	if len(keys) == 0 {
		return ssi.URI{}, nil, types.ErrKeyNotFound
	}
	publicKey, err := keys[0].PublicKey()
	if err != nil {
		return ssi.URI{}, nil, err
	}
	return keys[0].ID.URI(), publicKey, nil
}

func resolveRelationships(doc *did.Document, relationType types.RelationType) (relationships did.VerificationRelationships, err error) {
	switch relationType {
	case types.Authentication:
		return doc.Authentication, nil
	case types.AssertionMethod:
		return doc.AssertionMethod, nil
	case types.KeyAgreement:
		return doc.KeyAgreement, nil
	case types.CapabilityInvocation:
		return doc.CapabilityInvocation, nil
	case types.CapabilityDelegation:
		return doc.CapabilityDelegation, nil
	default:
		return nil, fmt.Errorf("unable to locate RelationType %v", relationType)
	}
}

// ServiceResolver is a wrapper around a DID store that allows resolving services, following references.
type ServiceResolver struct {
	Resolver types.DIDResolver
}

func (s ServiceResolver) Resolve(query ssi.URI, maxDepth int) (did.Service, error) {
	return s.ResolveEx(query, 0, maxDepth, map[string]*did.Document{})
}

func (s ServiceResolver) ResolveEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error) {
	if depth >= maxDepth {
		return did.Service{}, types.ErrServiceReferenceToDeep
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
		return did.Service{}, types.ErrServiceNotFound
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

// IsFunctionalResolveError returns true if the given error indicates the DID or service not being found or invalid,
// e.g. because it is deactivated, referenced too deeply, etc.
func IsFunctionalResolveError(target error) bool {
	return errors.Is(target, types.ErrNotFound) ||
		errors.Is(target, types.ErrDeactivated) ||
		errors.Is(target, types.ErrServiceNotFound) ||
		errors.Is(target, types.ErrNoActiveController) ||
		errors.Is(target, types.ErrServiceReferenceToDeep) ||
		errors.Is(target, did.InvalidDIDErr) ||
		errors.As(target, new(ServiceQueryError))
}
