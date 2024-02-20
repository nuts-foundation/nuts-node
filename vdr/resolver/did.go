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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"sync"
	"time"
)

// DIDResolver is the interface for DID resolvers: the process of getting the backing document of a DID.
type DIDResolver interface {
	// Resolve returns a DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata
	// It returns ErrDeactivated if the DID Document has been deactivated and metadata is unset or metadata.AllowDeactivated is false.
	// It returns ErrNoActiveController if all of the DID Documents controllers have been deactivated and metadata is unset or metadata.AllowDeactivated is false.
	Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error)
}

var _ DIDResolver = &ChainedDIDResolver{}

// ChainedDIDResolver is a DID resolver that tries to resolve the DID with multiple resolvers.
// E.g., it could first attempt a caching DID resolver, then a network DID resolver.
// If the first resolver returns ErrNotFound, the next resolver is tried.
// Other errors of the first resolver are returned immediately.
type ChainedDIDResolver struct {
	Resolvers []DIDResolver
}

func (c ChainedDIDResolver) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	for _, resolver := range c.Resolvers {
		document, metadata, err := resolver.Resolve(id, metadata)
		if err == nil {
			return document, metadata, nil
		} else if errors.Is(err, ErrNotFound) {
			continue
		} else {
			return nil, nil, err
		}
	}
	return nil, nil, ErrNotFound
}

// ErrDIDMethodNotSupported is returned when a DID method is not supported by the DID resolver
var ErrDIDMethodNotSupported = errors.New("DID method not supported")

// ErrDIDNotManagedByThisNode is returned when an operation needs the private key and if is not found on this host
var ErrDIDNotManagedByThisNode = errors.New("DID document not managed by this node")

// ErrNotFound The DID resolver was unable to find the DID document resulting from this resolution request.
var ErrNotFound = errors.New("unable to find the DID document")

// ErrDeactivated signals rejection due to document deactivation.
var ErrDeactivated = deactivatedError{msg: "the DID document has been deactivated"}

// ErrNoActiveController The DID supplied to the DID resolution does not have any active controllers.
var ErrNoActiveController = deactivatedError{msg: "no active controllers for DID Document"}

// BaseURLServiceType is type of the DID service which holds the base URL of the node's HTTP services,
// exposed to other Nuts nodes. E.g. OpenID4VCI or OAuth2 endpoints.
const BaseURLServiceType = "node-http-services-baseurl"

type deactivatedError struct {
	msg string
}

func (d deactivatedError) Error() string {
	return d.msg
}

func (d deactivatedError) Is(other error) bool {
	_, result := other.(deactivatedError)
	return result
}

// DocumentMetadata holds the metadata of a DID document
type DocumentMetadata struct {
	Created time.Time  `json:"created"`
	Updated *time.Time `json:"updated,omitempty"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash hash.SHA256Hash `json:"hash"`
	// PreviousHash of the previous version of this DID document
	PreviousHash *hash.SHA256Hash `json:"previousHash,omitempty"`
	// SourceTransactions points to the transaction(s) that created the current version of this DID Document.
	// If multiple transactions are listed, the DID Document is conflicted
	SourceTransactions []hash.SHA256Hash `json:"txs"`
	// Deactivated indicates if the document is deactivated
	Deactivated bool `json:"deactivated"`
}

// Copy creates a deep copy of DocumentMetadata
func (m DocumentMetadata) Copy() DocumentMetadata {
	if m.Updated != nil {
		updated := *m.Updated
		m.Updated = &updated
	}

	if m.PreviousHash != nil {
		prevHash := *m.PreviousHash
		m.PreviousHash = &prevHash
	}
	m.SourceTransactions = append(m.SourceTransactions[:0:0], m.SourceTransactions...)

	return m
}

// IsConflicted returns if a DID Document is conflicted
func (m DocumentMetadata) IsConflicted() bool {
	return len(m.SourceTransactions) > 1
}

// ResolveMetadata contains metadata for the resolver.
type ResolveMetadata struct {
	// Resolve the version which is valid at this time
	ResolveTime *time.Time
	// if provided, use the version which matches this exact hash
	Hash *hash.SHA256Hash
	// SourceTransaction must match a TX hash from the metadata.SourceTransaction field, if provided
	SourceTransaction *hash.SHA256Hash
	// Allow DIDs which are deactivated
	AllowDeactivated bool
}

var _ DIDResolver = &DIDResolverRouter{}

// DIDResolverRouter is a DID resolver that can route to different DID resolvers based on the DID method
type DIDResolverRouter struct {
	resolvers sync.Map
}

// Resolve looks up the right resolver for the given DID and delegates the resolution to it.
// If no resolver is registered for the given DID method, ErrDIDMethodNotSupported is returned.
func (r *DIDResolverRouter) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	method := id.Method
	didResolver, registered := r.resolvers.Load(method)
	if !registered {
		return nil, nil, ErrDIDMethodNotSupported
	}
	return didResolver.(DIDResolver).Resolve(id, metadata)
}

// Register registers a DID resolver for the given DID method.
func (r *DIDResolverRouter) Register(method string, resolver DIDResolver) {
	r.resolvers.Store(method, resolver)
}

// IsFunctionalResolveError returns true if the given error indicates the DID or service not being found or invalid,
// e.g. because it is deactivated, referenced too deeply, etc.
func IsFunctionalResolveError(target error) bool {
	return errors.Is(target, ErrNotFound) ||
		errors.Is(target, ErrDeactivated) ||
		errors.Is(target, ErrServiceNotFound) ||
		errors.Is(target, ErrNoActiveController) ||
		errors.Is(target, ErrServiceReferenceToDeep) ||
		errors.Is(target, did.InvalidDIDErr) ||
		errors.As(target, new(ServiceQueryError))
}

// GetDIDFromURL returns the DID from the given URL, stripping any query parameters, path segments and fragments.
func GetDIDFromURL(didURL string) (did.DID, error) {
	parsed, err := did.ParseDIDURL(didURL)
	if err != nil {
		return did.DID{}, err
	}
	return parsed.DID, nil
}

// IsDeactivated returns true if the DID.Document has already been deactivated
func IsDeactivated(document did.Document) bool {
	return len(document.Controller) == 0 && len(document.CapabilityInvocation) == 0
}
