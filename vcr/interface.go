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
	"embed"
	"errors"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

//go:embed assets/*
var defaultTemplates embed.FS

// ErrInvalidIssuer is returned when a credential is issued by a DID that is unknown or when the private key is missing.
var ErrInvalidIssuer = errors.New("invalid credential issuer")

// ErrInvalidSubject is returned when a credential is issued to a DID that is unknown or revoked.
var ErrInvalidSubject = errors.New("invalid credential subject")

// ErrNotFound is returned when a credential can not be found based on its ID.
var ErrNotFound = errors.New("credential not found")

// ErrRevoked is returned when a credential has been revoked and the required action requires it to not be revoked.
var ErrRevoked = errors.New("credential is revoked")

// ErrInvalidCredential is returned when validation failed
var ErrInvalidCredential = errors.New("invalid credential")

var vcDocumentType = "application/vc+json"

var revocationDocumentType = "application/vc+json;type=revocation"

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	StoreCredential(vc did.VerifiableCredential) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
}

// VCR is the interface that covers all functionality of the vcr store.
type VCR interface {
	// Issue creates and publishes a new VC.
	// An optional expirationDate can be given.
	// VCs are stored when the network has successfully published them.
	Issue(vc did.VerifiableCredential) (*did.VerifiableCredential, error)
	// Search for matching credentials based upon a query. It returns an empty list if no matches have been found.
	Search(query concept.Query) ([]did.VerifiableCredential, error)
	// Resolve returns a credential based on its ID. Returns an error when not found.
	Resolve(ID did.URI) (did.VerifiableCredential, error)
	// Verify checks if a credential is valid and trusted at the given time.
	// The time check is optional, so credentials can be issued that will become valid.
	// If valid no error is returned.
	Verify(vc did.VerifiableCredential, at *time.Time) error
	// Revoke a credential based on its ID, the Issuer will be resolved automatically.
	// The CurrentStatus will be set to 'Revoked' and the statusDate to the current time.
	// It returns an error if the credential, issuer or private key can not be found.
	Revoke(ID did.URI) (*credential.Revocation, error)
	// IsRevoked returns true when a revocation exists for a credential
	IsRevoked(ID did.URI) (bool, error)
	// Registry returns the concept registry
	Registry() concept.Registry

	Writer
}
