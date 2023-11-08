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

package management

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// DocCreator is the interface that wraps the Create method
type DocCreator interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated.
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto.Key, error)
}

// DocUpdater is the interface that defines functions that alter the state of a DID document
type DocUpdater interface {
	// Update replaces the DID document identified by DID with the nextVersion
	// If the DID Document is not found, ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	Update(ctx context.Context, id did.DID, next did.Document) error
}

// DocManipulator groups several higher level methods to alter the state of a DID document.
type DocManipulator interface {
	// Deactivate deactivates a DID document
	// Deactivation will be done in such a way that a DID doc cannot be used / activated anymore.
	// Since the deactivation is definitive, no version is required
	// If the DID Document is not found ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	// If the DID Document is already deactivated ErrDeactivated is returned
	Deactivate(ctx context.Context, id did.DID) error

	// RemoveVerificationMethod removes a VerificationMethod from a DID document.
	// It accepts the id DID as identifier for the DID document.
	// It accepts the kid DID as identifier for the VerificationMethod.
	// It returns an ErrNotFound when the DID document could not be found.
	// It returns an ErrNotFound when there is no VerificationMethod with the provided kid in the document.
	// It returns an ErrDeactivated when the DID document has the deactivated state.
	// It returns an ErrDIDNotManagedByThisNode if the DID document is not managed by this node.
	RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error

	// AddVerificationMethod generates a new key and adds it, wrapped as a VerificationMethod, to a DID document.
	// It accepts a DID as identifier for the DID document.
	// It returns an ErrNotFound when the DID document could not be found.
	// It returns an ErrDeactivated when the DID document has the deactivated state.
	// It returns an ErrDIDNotManagedByThisNode if the DID document is not managed by this node.
	AddVerificationMethod(ctx context.Context, id did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error)
}

// DIDCreationOptions defines options for creating a DID Document.
type DIDCreationOptions struct {
	// Controllers lists the DIDs that can control the new DID Document. If selfControl = true and controllers is not empty,
	// the newly generated DID will be added to the list of controllers.
	Controllers []did.DID

	// KeyFlags specifies for what purposes the generated key can be used
	KeyFlags DIDKeyFlags

	// SelfControl indicates whether the generated DID Document can be altered with its own capabilityInvocation key.
	// Defaults to true when not given.
	SelfControl bool
}

// DIDKeyFlags is a bitmask used for specifying for what purposes a key in a DID document can be used (a.k.a. Verification Method relationships).
type DIDKeyFlags uint

// Is returns whether the specified DIDKeyFlags is enabled.
func (k DIDKeyFlags) Is(other DIDKeyFlags) bool {
	return k&other == other
}

const (
	// AssertionMethodUsage indicates if the generated key pair can be used for assertions.
	AssertionMethodUsage DIDKeyFlags = 1 << iota
	// AuthenticationUsage indicates if the generated key pair can be used for authentication.
	AuthenticationUsage
	// CapabilityDelegationUsage indicates if the generated key pair can be used for altering DID Documents.
	CapabilityDelegationUsage
	// CapabilityInvocationUsage indicates if the generated key pair can be used for capability invocations.
	CapabilityInvocationUsage
	// KeyAgreementUsage indicates if the generated key pair can be used for Key agreements.
	KeyAgreementUsage
)

// DocumentOwner is the interface for checking DID document ownership (presence of private keys).
type DocumentOwner interface {
	// IsOwner returns true if the DID Document is owned by the node, meaning there are private keys present for the DID Document.
	IsOwner(context.Context, did.DID) (bool, error)
	// ListOwned returns all the DIDs owned by the node.
	ListOwned(ctx context.Context) ([]did.DID, error)
}
