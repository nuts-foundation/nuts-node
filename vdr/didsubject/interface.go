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
	"github.com/nuts-foundation/nuts-node/storage/orm"
)

// ErrInvalidService is returned when a service is invalid, e.g. invalid field values, duplicate ID, not found, etc.
var ErrInvalidService = errors.New("invalid DID document service")

// ErrUnsupportedDIDMethod is returned when a DID method is not supported.
var ErrUnsupportedDIDMethod = errors.New("unsupported DID method")

// MethodManager keeps DID method specific state in sync with the DID sql database.
type MethodManager interface {
	// NewDocument generates a new DID document for the given subject.
	// This is done by the method manager since the DID might depend on method specific rules.
	NewDocument(ctx context.Context, keyFlags orm.DIDKeyFlags) (*orm.DidDocument, error)
	// NewVerificationMethod generates a new VerificationMethod for the given subject.
	// This is done by the method manager since the VM ID might depend on method specific rules.
	// If keyUsage includes management.KeyAgreement, an RSA key is generated, otherwise an EC key.
	// RSA keys are not yet fully supported, see https://github.com/nuts-foundation/nuts-node/issues/1948
	NewVerificationMethod(ctx context.Context, controller did.DID, keyFlags orm.DIDKeyFlags) (*did.VerificationMethod, error)
	// Commit is called after changes are made to the primary db.
	// On success, the caller will remove/update the DID changelog.
	Commit(ctx context.Context, event orm.DIDChangeLog) error
	// IsCommitted checks if the event is already committed for the specific method.
	// A mismatch can occur if the method commits before the db is updated (db failure).
	// If a change is not committed, a rollback of the primary db will occur (delete of that version)
	IsCommitted(ctx context.Context, event orm.DIDChangeLog) (bool, error)
}

// DocumentManager is the interface that groups several higher level methods to create and update DID documents.
// Deprecated
// Only used for V1 API calls.
type DocumentManager interface {
	// Update replaces the DID document identified by DID with the nextVersion
	// Deprecated: only did:nuts implements it, new methods should higher level functions, then this method can become private
	// If the DID Document is not found, ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	Update(ctx context.Context, id did.DID, next did.Document) error

	// RemoveVerificationMethod removes a VerificationMethod from a DID document.
	// Deprecated: only relevant for v1 API calls.
	// It accepts the id DID as identifier for the DID document.
	// It accepts the kid DID as identifier for the VerificationMethod.
	// It returns an ErrNotFound when the DID document could not be found.
	// It returns an ErrNotFound when there is no VerificationMethod with the provided kid in the document.
	// It returns an ErrDeactivated when the DID document has the deactivated state.
	// It returns an ErrDIDNotManagedByThisNode if the DID document is not managed by this node.
	RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error
}

// Manager abstracts DID Document management away from the API caller.
// It manages DIDs for a DID subject.
type Manager interface {
	// Create creates a new DID document for each method and returns them.
	// The DID subject is also returned
	Create(ctx context.Context, options CreationOptions) ([]did.Document, string, error)

	// Deactivate deactivates DID documents for a subject, making it unusable for future interactions.
	// If no documents are found, an error is returned.
	Deactivate(ctx context.Context, subject string) error

	// List returns all subjects and their DIDs.
	List(ctx context.Context) (map[string][]did.DID, error)

	// ListDIDs returns all DIDs for a subject
	ListDIDs(ctx context.Context, subject string) ([]did.DID, error)

	// Exists returns true if the subject exists
	Exists(ctx context.Context, subject string) (bool, error)

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
	AddVerificationMethod(ctx context.Context, subject string, keyUsage orm.DIDKeyFlags) ([]did.VerificationMethod, error)

	// Rollback queries the did_change_log table for all changes that are older than 1 minute.
	// Any entry that's still there is considered not committed and will be rolled back.
	// All DID Document versions that are part of the same transaction_id will be deleted.
	// This works because did:web is always committed and did:nuts might not be. So the DB state actually only depends on the result of the did:nuts network operation result.
	Rollback(ctx context.Context)
}

// DocumentMigration is used to migrate DID document versions to the SQL DB. This should only be used for DID documents managed by this node.
type DocumentMigration interface {
	// MigrateDIDHistoryToSQL is used to migrate the history of a DID Document to SQL.
	// It adds all versions of a DID Document up to a deactivated version. Any changes after a deactivation are not migrated.
	// getHistory retrieves the history of the DID since the requested version.
	MigrateDIDHistoryToSQL(id did.DID, subject string, getHistory func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error)) error
}

// SubjectCreationOption links all create DIDs to the DID Subject
type SubjectCreationOption struct {
	Subject string
}

// EncryptionKeyCreationOption signals that a separate RSA key should be created for encryption purposes.
type EncryptionKeyCreationOption struct{}

// SkipAssertionKeyCreationOption signals that no assertion key should be created.
type SkipAssertionKeyCreationOption struct{}

// NutsLegacyNamingOption will make the subject equal to the Nuts DID.
type NutsLegacyNamingOption struct{}

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

// DocumentOwner is the interface for checking DID document ownership (presence of private keys).
type DocumentOwner interface {
	// IsOwner returns true if the DID Document is owned by the node, meaning there are private keys present for the DID Document.
	IsOwner(context.Context, did.DID) (bool, error)
	// ListOwned returns all the DIDs owned by the node.
	ListOwned(ctx context.Context) ([]did.DID, error)
}
