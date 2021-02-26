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

package vcr

import (
	"errors"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
)

// ErrInvalidIssuer is returned when a vcr is issued by a DID that is unknown or when the private key is missing.
var ErrInvalidIssuer = errors.New("invalid vcr issuer")

// ErrInvalidSubject is returned when a vcr is issued to a DID that is unknown or revoked.
var ErrInvalidSubject = errors.New("invalid vcr subject")

// ErrNotFound is returned when a vcr can not be found based on its ID.
var ErrNotFound = errors.New("vcr not found")

// Issuer can issue credentials for DIDs to DIDs.
type Issuer interface {
	// Issue creates and publishes a new vcr.
	// An optional expirationDate can be given.
	// VCs are stored when the network has successfully published them.
	Issue(issuer did.DID, subject did.DID, vcType string, credentialSubject interface{}, expirationDate *time.Time) (did.VerifiableCredential, error)
}

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// Write writes a VC to storage.
	Write(vc did.VerifiableCredential) error
}

// VCR is the interface that covers all functionality of the vcr store.
type VCR interface {
	// Search for matching credentials based upon a query. It returns an empty list if no matches have been found.
	Search(query concept.Query) ([]did.VerifiableCredential, error)
	// Resolve returns a vcr based on its ID. Returns an error when not found.
	// todo: not implemented yet and subject to change
	Resolve(ID string) (did.VerifiableCredential, error)
	// Verify checks if a vcr is valid and trusted at the given time.
	// todo: not implemented yet and subject to change
	Verify(vc did.VerifiableCredential, credentialSubject interface{}, at time.Time) (bool, error)
	// Registry returns the concept registry
	Registry() concept.Registry

	//Writer
	//Issuer
}
