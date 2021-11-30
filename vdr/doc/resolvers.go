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

// Package doc contains DID Document related functionality that only matters to the current node.
// All functionality here has zero relations to the network.
package doc

import (
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrNestedDocumentsTooDeep is returned when a DID Document contains a multiple services with the same type
var ErrNestedDocumentsTooDeep = errors.New("DID Document controller structure has too many indirections")

const serviceTypeQueryParameter = "type"
const serviceEndpointPath = "serviceEndpoint"

const maxControllerDepth = 5

// Resolver implements the DocResolver interface with a types.Store as backend
type Resolver struct {
	Store types.Store
}

func (d Resolver) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	return d.resolve(id, metadata, 0)
}

// bug, if one is deactivated => error
func (d Resolver) resolve(id did.DID, metadata *types.ResolveMetadata, depth int) (*did.Document, *types.DocumentMetadata, error) {
	if depth >= maxControllerDepth {
		return nil, nil, ErrNestedDocumentsTooDeep
	}

	doc, meta, err := d.Store.Resolve(id, metadata)
	if err != nil {
		return nil, nil, err
	}

	if metadata != nil && !metadata.AllowDeactivated {
		// also check if the controller is not deactivated
		// since ResolveControllers calls Resolve and propagates the metadata
		controllers, err := d.resolveControllers(*doc, metadata, depth+1)
		if err != nil {
			return nil, nil, err
		}
		if len(controllers) == 0 {
			return nil, nil, types.ErrNoActiveController
		}
	}

	return doc, meta, nil
}

// ResolveControllers finds the DID Document controllers
func (d Resolver) ResolveControllers(doc did.Document, metadata *types.ResolveMetadata) ([]did.Document, error) {
	return d.resolveControllers(doc, metadata, 0)
}

// ResolveControllers finds the DID Document controllers
func (d Resolver) resolveControllers(doc did.Document, metadata *types.ResolveMetadata, depth int) ([]did.Document, error) {
	var leaves []did.Document
	var refsToResolve []did.DID

	if len(doc.Controller) == 0 && len(doc.CapabilityInvocation) > 0 {
		// no controller -> doc is its own controller
		leaves = append(leaves, doc)
	} else {
		for _, ctrlDID := range doc.Controller {
			if doc.ID.Equals(ctrlDID) {
				if len(doc.CapabilityInvocation) > 0 {
					// doc is its own controller
					leaves = append(leaves, doc)
				}
			} else {
				// add did to be resolved later
				refsToResolve = append(refsToResolve, ctrlDID)
			}
		}
	}

	// resolve all unresolved docs
	for _, ref := range refsToResolve {
		node, _, err := d.resolve(ref, metadata, depth)
		if errors.Is(err, types.ErrDeactivated) || errors.Is(err, types.ErrNoActiveController) {
			continue
		}
		if errors.Is(err, ErrNestedDocumentsTooDeep) {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("unable to resolve controllers: %w", err)
		}
		leaves = append(leaves, *node)
	}

	// filter deactivated
	j := 0
	for _, leaf := range leaves {
		if !isDeactivated(leaf) {
			leaves[j] = leaf
			j++
		}
	}

	return leaves[:j], nil
}

func isDeactivated(document did.Document) bool {
	return len(document.Controller) == 0 && len(document.CapabilityInvocation) == 0
}

// KeyResolver implements the KeyResolver interface with a types.Store as backend
type KeyResolver struct {
	Store types.Store
}

// ResolveSigningKeyID resolves the ID of the first valid AssertionMethod for a indicated DID document at a given time.
func (r KeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := r.Store.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	if len(doc.AssertionMethod) == 0 {
		return "", types.ErrKeyNotFound
	}
	return doc.AssertionMethod[0].ID.String(), nil
}

// ResolveSigningKey resolves the PublicKey of the first valid AssertionMethod for an indicated
// DID document at a validAt time.
func (r KeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	kid, err := did.ParseDIDURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	holder := *kid
	holder.Fragment = ""
	doc, _, err := r.Store.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	var result *did.VerificationRelationship
	for _, rel := range doc.AssertionMethod {
		if rel.ID.String() == keyID {
			result = &rel
		}
	}
	if result == nil {
		return "", types.ErrKeyNotFound
	}
	return result.PublicKey()
}

// ResolveAssertionKeyID resolves the id of the first valid AssertionMethod of an indicated DID document in the current state.
func (r KeyResolver) ResolveAssertionKeyID(id did.DID) (ssi.URI, error) {
	doc, _, err := r.Store.Resolve(id, nil)
	if err != nil {
		return ssi.URI{}, err
	}

	return ExtractAssertionKeyID(*doc)
}

// ExtractAssertionKeyID returns a assertionMethod ID from the given DID document.
// it returns types.ErrKeyNotFound is no assertionMethod key is present.
func ExtractAssertionKeyID(doc did.Document) (ssi.URI, error) {
	keys := doc.AssertionMethod
	for _, key := range keys {
		kid := key.ID.String()
		u, _ := ssi.ParseURI(kid)
		return *u, nil
	}

	return ssi.URI{}, types.ErrKeyNotFound
}

func (r KeyResolver) ResolvePublicKeyInTime(kid string, validAt *time.Time) (crypto.PublicKey, error) {
	return r.resolvePublicKey(kid, types.ResolveMetadata{
		ResolveTime: validAt,
	})
}

func (r KeyResolver) ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error) {
	// try all keys, continue when err == types.ErrNotFound
	for _, h := range sourceTransactionsRefs {
		publicKey, err := r.resolvePublicKey(kid, types.ResolveMetadata{
			SourceTransaction: &h,
		})
		if err == nil {
			return publicKey, nil
		}
		if err != types.ErrNotFound {
			return nil, err
		}
	}

	return nil, types.ErrNotFound
}

func (r KeyResolver) resolvePublicKey(kid string, metadata types.ResolveMetadata) (crypto.PublicKey, error) {
	did, err := did.ParseDIDURL(kid)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", kid, err)
	}
	didCopy := *did
	didCopy.Fragment = ""
	doc, _, err := r.Store.Resolve(didCopy, &metadata)
	if err != nil {
		return nil, err
	}

	vm := doc.VerificationMethod.FindByID(*did)
	if vm == nil {
		return nil, types.ErrKeyNotFound
	}

	return vm.PublicKey()
}

type ServiceResolver interface {
	// ResolveService looks up the DID document of the specified query and then tries to find the service with the specified type.
	// The query must be in the form of a service query, e.g. `did:nuts:12345/serviceEndpoint?type=some-type`.
	// The maxDepth indicates how deep references are followed. If maxDepth = 0, no references are followed (and an error is returned if the given query resolves to a reference).
	// If the DID document or service is not found, a reference can't be resolved or the references exceed maxDepth, an error is returned.
	ResolveService(query ssi.URI, maxDepth int) (did.Service, error)

	// ResolveServiceEx tries to resolve a DID service from the given endpoint URI, following references (URIs that begin with 'did:').
	// When the endpoint is a reference it resolves it up until the (per spec) max reference depth. When resolving a reference it recursively calls itself with depth + 1.
	// The documentCache map is used to avoid resolving the same document over and over again, which might be a (slightly more) expensive operation.
	ResolveServiceEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error)
}

func NewServiceResolver(documentResolver types.DocResolver) ServiceResolver {
	return &serviceResolver{doc: documentResolver}
}

type serviceResolver struct {
	doc types.DocResolver
}

// ResolveService looks up the DID document of the specified query and then tries to find the service with the specified type.
// The query must be in the form of a service query, e.g. `did:nuts:12345/serviceEndpoint?type=some-type`.
// The maxDepth indicates how deep references are followed. If maxDepth = 0, no references are followed (and an error is returned if the given query resolves to a reference).
// If the DID document or service is not found, a reference can't be resolved or the references exceed maxDepth, an error is returned.
func (s serviceResolver) ResolveService(query ssi.URI, maxDepth int) (did.Service, error) {
	return s.ResolveServiceEx(query, 0, maxDepth, map[string]*did.Document{})
}

// ResolveServiceEx tries to resolve a DID service from the given endpoint URI, following references (URIs that begin with 'did:').
// When the endpoint is a reference it resolves it up until the (per spec) max reference depth. When resolving a reference it recursively calls itself with depth + 1.
// The documentCache map is used to avoid resolving the same document over and over again, which might be a (slightly more) expensive operation.
func (s serviceResolver) ResolveServiceEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error) {
	if depth >= maxDepth {
		return did.Service{}, types.ErrServiceReferenceToDeep
	}

	referencedDID, err := did.ParseDIDURL(endpoint.String())
	if err != nil {
		// Shouldn't happen, because only DID URLs are passed?
		return did.Service{}, err
	}
	referencedDID.Query = ""
	referencedDID.Path = ""
	referencedDID.Fragment = ""
	referencedDID.PathSegments = nil
	var document *did.Document
	if document = documentCache[referencedDID.String()]; document == nil {
		document, _, err = s.doc.Resolve(*referencedDID, nil)
		if err != nil {
			return did.Service{}, err
		}
		documentCache[referencedDID.String()] = document
	}

	var service *did.Service
	for _, curr := range document.Service {
		if curr.Type == endpoint.Query().Get(serviceTypeQueryParameter) {
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
			return s.ResolveServiceEx(*resolvedEndpointURI, depth+1, maxDepth, documentCache)
		}
	}
	return *service, nil
}

func MakeServiceReference(subjectDID did.DID, serviceType string) ssi.URI {
	ref := subjectDID.URI()
	ref.Path = "/" + serviceEndpointPath
	ref.RawQuery = fmt.Sprintf("%s=%s", serviceTypeQueryParameter, serviceType)
	return ref
}

// IsServiceReference checks whether the given endpoint string looks like a service reference (e.g. did:nuts:1234/serviceType?type=HelloWorld).
func IsServiceReference(endpoint string) bool {
	return strings.HasPrefix(endpoint, "did:")
}

func ValidateServiceReference(endpointURI ssi.URI) error {
	// Parse it as DID URL since DID URLs are rootless and thus opaque (RFC 3986), meaning the path will be part of the URI body, rather than the URI path.
	// For DID URLs the path is parsed properly.
	didEndpointURL, err := did.ParseDIDURL(endpointURI.String())
	if err != nil {
		return types.ErrInvalidServiceQuery
	}
	if didEndpointURL.Path != serviceEndpointPath {
		// Service reference doesn't refer to `/serviceEndpoint`
		return types.ErrInvalidServiceQuery
	}
	queriedServiceType := endpointURI.Query().Get(serviceTypeQueryParameter)
	if len(queriedServiceType) == 0 {
		// Service reference doesn't contain `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	if len(endpointURI.Query()[serviceTypeQueryParameter]) > 1 {
		// Service reference contains more than 1 `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	if len(endpointURI.Query()) > 1 {
		// Service reference contains more than just `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	return nil
}
