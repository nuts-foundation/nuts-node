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
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// ErrInvalidService is returned when a service is invalid, e.g. invalid field values, duplicate ID, not found, etc.
var ErrInvalidService = errors.New("invalid DID document service")

// ErrUnsupportedDIDMethod is returned when a DID method is not supported.
var ErrUnsupportedDIDMethod = errors.New("unsupported DID method")

// ErrDIDAlreadyExists is returned when a DID already exists.
var ErrDIDAlreadyExists = errors.New("DID already exists")

// DocumentManager is the interface that groups several higher level methods to create and update DID documents.
type DocumentManager interface {
	DocCreator
	resolver.DIDResolver

	// Deactivate deactivates a DID document, making it unusable for future interactions.
	Deactivate(ctx context.Context, id did.DID) error

	// CreateService creates a new service in the DID document identified by subjectDID.
	// If the service DID is not provided, it will be generated.
	CreateService(ctx context.Context, subjectDID did.DID, service did.Service) (*did.Service, error)

	// UpdateService updates a service in the DID document identified by subjectDID.
	UpdateService(ctx context.Context, subjectDID did.DID, serviceID ssi.URI, service did.Service) (*did.Service, error)

	// DeleteService deletes a service in the DID document identified by subjectDID.
	// It returns an error if the DID or service isn't found.
	DeleteService(ctx context.Context, subjectDID did.DID, serviceID ssi.URI) error
}

// DocCreator is the interface that wraps the Create method
type DocCreator interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated.
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create(ctx context.Context, options CreationOptions) (*did.Document, crypto.Key, error)
}

// DocUpdater is the interface that defines functions that alter the state of a DID document
// Deprecated: only did:nuts implements it, new methods should implement DocumentManager
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

	// CreateService creates a new service in the DID document identified by subjectDID.
	// If the service DID is not provided, it will be generated.
	CreateService(ctx context.Context, subjectDID did.DID, service did.Service) (*did.Service, error)

	// UpdateService updates a service in the DID document identified by subjectDID.
	UpdateService(ctx context.Context, subjectDID did.DID, serviceID ssi.URI, service did.Service) (*did.Service, error)

	// DeleteService deletes a service in the DID document identified by subjectDID.
	// It returns an error if the DID or service isn't found.
	DeleteService(ctx context.Context, subjectDID did.DID, serviceID ssi.URI) error
}

// Create returns empty CreationOptions with the given method set.
func Create(method string) CreationOptions {
	return defaultDIDCreationOptions{
		method: method,
	}
}

// CreationOptions defines options for creating a DID Document.
type CreationOptions interface {
	// Method returns the DID method name.
	Method() string
	// With adds an option to the CreationOptions.
	// It returns a new CreationOptions instance.
	// If the same option is specified multiple times, the last instance will be used.
	With(option CreationOption) CreationOptions
	// All returns all the options.
	All() []CreationOption
}

type defaultDIDCreationOptions struct {
	method string
	opts   []CreationOption
}

func (d defaultDIDCreationOptions) All() []CreationOption {
	return append([]CreationOption{}, d.opts...)
}

func (d defaultDIDCreationOptions) With(opt CreationOption) CreationOptions {
	d.opts = append(d.opts, opt)
	return &d
}

func (d defaultDIDCreationOptions) Method() string {
	return d.method
}

type CreationOption interface {
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
