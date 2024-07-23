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

package didsubject

import (
	"context"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// ErrInvalidService is returned when a service is invalid, e.g. invalid field values, duplicate ID, not found, etc.
var ErrInvalidService = errors.New("invalid DID document service")

// ErrUnsupportedDIDMethod is returned when a DID method is not supported.
var ErrUnsupportedDIDMethod = errors.New("unsupported DID method")

// ErrDIDAlreadyExists is returned when a DID already exists.
var ErrDIDAlreadyExists = errors.New("DID already exists")

// DocumentManager is the interface that groups several higher level methods to create and update DID documents.
// Only used for V1 API calls.
type DocumentManager interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated.
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create(ctx context.Context, options CreationOptions) (*did.Document, crypto.Key, error)

	// Update replaces the DID document identified by DID with the nextVersion
	// Deprecated: only did:nuts implements it, new methods should higher level functions, then this method can become private
	// If the DID Document is not found, ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	Update(ctx context.Context, id did.DID, next did.Document) error

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

// SubjectManager abstracts DID Document management away from the API caller.
// It manages DIDs for a DID subject.
type SubjectManager interface {
	// Create creates a new DID document for each method and returns them.
	// The DID subject is also returned
	Create(ctx context.Context, options CreationOptions) ([]did.Document, string, error)

	// Deactivate deactivates DID documents for a subject, making it unusable for future interactions.
	// If no documents are found, an error is returned.
	Deactivate(ctx context.Context, subject string) error

	// List returns all DIDs for a subject
	List(ctx context.Context, subject string) ([]did.DID, error)

	// CreateService creates a new service in DID documents for the given subject.
	// The service ID will be generated.
	CreateService(ctx context.Context, subject string, service did.Service) ([]did.Service, error)

	// FindServices returns services for a given subject matching type if given.
	// Duplicate services (based on ID) are ignored.
	FindServices(ctx context.Context, subject string, serviceType *string) ([]did.Service, error)

	// UpdateService updates a service in the DID document identified by serviceID.
	// It'll match any service for the subject based on the fragment. This allows for updating services across multiple DID methods.
	UpdateService(ctx context.Context, subject string, serviceID ssi.URI, service did.Service) ([]did.Service, error)

	// DeleteService deletes services in the DID documents for a given subject.
	// It'll match any service for the subject based on the fragment.
	// It returns an error if no services have been deleted.
	DeleteService(ctx context.Context, subject string, serviceID ssi.URI) error

	// AddVerificationMethod generates new keys and adds them, wrapped as a VerificationMethod, to all DID documents of a subject.
	// For each DID method a new key will be generated.
	// It returns an ErrNotFound when the subject could not be found.
	// It returns an ErrDeactivated when the subject has the deactivated state.
	AddVerificationMethod(ctx context.Context, subject string, keyUsage DIDKeyFlags) ([]did.VerificationMethod, error)
}

// SubjectCreationOption links all create DIDs to the DID Subject
type SubjectCreationOption struct {
	Subject string
}

// EncryptionKeyCreationOption signals that a separate RSA key should be created for encryption purposes.
type EncryptionKeyCreationOption struct{}

// SkipAssertionKeyCreationOption signals that no assertion key should be created.
type SkipAssertionKeyCreationOption struct{}

// CreationOptions defines options for creating DID Documents.
type CreationOptions interface {
	// With adds an option to the CreationOptions.
	// It returns a new CreationOptions instance.
	// If the same option is specified multiple times, the last instance will be used.
	With(option CreationOption) CreationOptions
	// All returns all the options.
	All() []CreationOption
}

// DefaultCreationOptions returns a default CreationOptions instance.
func DefaultCreationOptions() CreationOptions {
	return &defaultDIDCreationOptions{}
}

type defaultDIDCreationOptions struct {
	opts []CreationOption
}

func (d defaultDIDCreationOptions) All() []CreationOption {
	return append([]CreationOption{}, d.opts...)
}

func (d defaultDIDCreationOptions) With(opt CreationOption) CreationOptions {
	d.opts = append(d.opts, opt)
	return &d
}

type CreationOption interface {
}

// DIDKeyFlags is a bitmask used for specifying for what purposes a key in a DID document can be used (a.k.a. Verification Method relationships).
type DIDKeyFlags uint

// Is returns whether the specified DIDKeyFlags is enabled.
func (k DIDKeyFlags) Is(other DIDKeyFlags) bool {
	return k&other > 0
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

func AssertionKeyUsage() DIDKeyFlags {
	return CapabilityInvocationUsage | AssertionMethodUsage | AuthenticationUsage | CapabilityDelegationUsage
}

func EncryptionKeyUsage() DIDKeyFlags {
	return KeyAgreementUsage
}

// DocumentOwner is the interface for checking DID document ownership (presence of private keys).
type DocumentOwner interface {
	// IsOwner returns true if the DID Document is owned by the node, meaning there are private keys present for the DID Document.
	IsOwner(context.Context, did.DID) (bool, error)
	// ListOwned returns all the DIDs owned by the node.
	ListOwned(ctx context.Context) ([]did.DID, error)
}
