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
 */

package types

import (
	"errors"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// ErrUpdateOnOutdatedData is returned when a concurrent update is done on a DID document.
var ErrUpdateOnOutdatedData = errors.New("could not update outdated DID document")

// ErrKeyNotFound is returned when a particular key or type of key is not found.
var ErrKeyNotFound = errors.New("key not found in DID document")

// ErrDIDNotManagedByThisNode is returned when an operation needs the private key and if is not found on this host
var ErrDIDNotManagedByThisNode = errors.New("DID document not managed by this node")

// ErrNotFound The DID resolver was unable to find the DID document resulting from this resolution request.
var ErrNotFound = errors.New("unable to find the DID document")

// ErrDeactivated The DID supplied to the DID resolution function has been deactivated.
var ErrDeactivated = deactivatedError{msg: "the DID document has been deactivated"}

// ErrNoActiveController The DID supplied to the DID resolution does not have any active controllers.
var ErrNoActiveController = deactivatedError{msg: "no active controllers for DID Document"}

// ErrDIDAlreadyExists is returned when a DID already exists.
var ErrDIDAlreadyExists = errors.New("DID document already exists in the store")

// ErrDuplicateService is returned when a DID Document contains a multiple services with the same type
var ErrDuplicateService = errors.New("service type is duplicate")

// ErrServiceNotFound is returned when the service is not found on a DID
var ErrServiceNotFound = errors.New("service not found in DID Document")

// ErrServiceReferenceToDeep is returned when a service reference is chain is nested too deeply.
var ErrServiceReferenceToDeep = errors.New("service references are nested to deeply before resolving to a non-reference")

// ErrInvalidServiceQuery is returned when a compound service contains an invalid service reference.
var ErrInvalidServiceQuery = errors.New("service query is invalid")

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

// CompoundService is a service type that can be used as target for github.com/nuts-foundation/go-did/did/document.go#UnmarshalServiceEndpoint
type CompoundService map[string]string

// DIDCreationOptions defines options for creating a DID Document.
type DIDCreationOptions struct {

	// Controllers lists the DIDs that can control the new DID Document. If selfControl = true and controllers is not empty,
	// the newly generated DID will be added to the list of controllers.
	Controllers []did.DID

	// AssertionMethod indicates if the generated key pair can be used for assertions.
	AssertionMethod bool

	// Authentication indicates if the generated key pair can be used for authentication.
	Authentication bool

	// CapabilityDelegation indicates if the generated key pair can be used for altering DID Documents.
	// In combination with selfControl = true, the key can be used to alter the new DID Document.
	// Defaults to true when not given.
	CapabilityDelegation bool

	// CapabilityInvocation indicates if the generated key pair can be used for capability invocations.
	CapabilityInvocation bool

	// KeyAgreement indicates if the generated key pair can be used for Key agreements.
	KeyAgreement bool

	// SelfControl indicates wether the generated DID Document can be altered with its own capabilityInvocation key.
	// Defaults to true when not given.
	SelfControl bool
}
