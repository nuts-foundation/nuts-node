/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// ErrUpdateOnOutdatedData is returned when a concurrent update is done on a DID document.
var ErrUpdateOnOutdatedData = errors.New("could not update outdated DID document")

// ErrInvalidDID The DID supplied to the DID resolution function does not conform to valid syntax.
var ErrInvalidDID = errors.New("invalid DID syntax")

// ErrKeyNotFound is returned when a particular key or type of key is not found.
var ErrKeyNotFound = errors.New("key not found in DID document")

// ErrDIDNotManagedByThisNode is returned when an operation needs the private key and if is not found on this host
var ErrDIDNotManagedByThisNode = errors.New("DID document not managed by this node")

// ErrNotFound The DID resolver was unable to find the DID document resulting from this resolution request.
var ErrNotFound = errors.New("unable to find the DID document")

// ErrDeactivated The DID supplied to the DID resolution function has been deactivated.
var ErrDeactivated = errors.New("the DID document has been deactivated")

// ErrDIDAlreadyExists is returned when a DID already exists.
var ErrDIDAlreadyExists = errors.New("DID document already exists in the store")

// DocumentMetadata holds the metadata of a DID document
type DocumentMetadata struct {
	Created time.Time  `json:"created"`
	Updated *time.Time `json:"updated,omitempty"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash hash.SHA256Hash `json:"hash"`
	// Deactivated indicates if the document is deactivated
	Deactivated bool `json:"deactivated"`
}

// Copy creates a deep copy of DocumentMetadata
func (m DocumentMetadata) Copy() DocumentMetadata {
	if m.Updated != nil {
		updated := *m.Updated
		m.Updated = &updated
	}
	return m
}

// ResolveMetadata contains metadata for the resolver.
type ResolveMetadata struct {
	// Resolve the version which is valid at this time
	ResolveTime *time.Time
	// if provided, use the version which matches this exact hash
	Hash *hash.SHA256Hash
	// Allow DIDs which are deactivated
	AllowDeactivated bool
}
