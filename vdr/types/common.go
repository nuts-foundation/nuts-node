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
var ErrUpdateOnOutdatedData = errors.New("could not update outdated document")

// ErrInvalidDID The DID supplied to the DID resolution function does not conform to valid syntax.
var ErrInvalidDID = errors.New("invalid did syntax")

// ErrNotFound The DID resolver was unable to find the DID document resulting from this resolution request.
var ErrNotFound = errors.New("unable to find the did document")

// ErrDeactivated The DID supplied to the DID resolution function has been deactivated.
var ErrDeactivated = errors.New("the document has been deactivated")

// ErrDIDAlreadyExists is returned when a DID already exists.
var ErrDIDAlreadyExists = errors.New("did document already exists in the store")

// DocumentMetadata holds the metadata of a DID document
type DocumentMetadata struct {
	Created time.Time  `json:"created"`
	Updated *time.Time `json:"updated,omitempty"`
	// Version contains the semantic version of the DID document.
	Version int `json:"version"`
	// TimelineID contains the hash of the JWS envelope of the first version of the DID document.
	TimelineID hash.SHA256Hash `json:"timelineID"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash hash.SHA256Hash `json:"hash"`
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
