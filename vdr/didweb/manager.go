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

package didweb

import (
	"context"
	crypt "crypto"
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"net/url"
	"strings"
)

func DefaultCreationOptions() management.CreationOptions {
	return management.Create(MethodName)
}

type userIDOption struct {
	id string
}

// UserID is an option to set a user for the did:web document.
// It will be used as last path part of the DID.
func UserID(id string) management.CreationOption {
	return userIDOption{id: id}
}

type didOption struct {
	value did.DID
}

// DID is an option to set the DID for the did:web document.
func DID(did did.DID) management.CreationOption {
	return didOption{value: did}
}

var _ management.DocumentManager = (*Manager)(nil)

// NewManager creates a new Manager to create and update did:web DID documents.
func NewManager(baseURL url.URL, keyStore crypto.KeyStore, db *gorm.DB) *Manager {
	return &Manager{
		store:    &sqlStore{db: db},
		baseURL:  baseURL,
		keyStore: keyStore,
	}
}

// Manager creates and updates did:web documents
type Manager struct {
	baseURL  url.URL
	store    store
	keyStore crypto.KeyStore
}

func (m Manager) Deactivate(ctx context.Context, subjectDID did.DID) error {
	verificationMethods, _, err := m.store.get(subjectDID)
	if err != nil {
		return err
	}
	if err := m.store.delete(subjectDID); err != nil {
		return err
	}
	var deleteErrors []error
	for _, verificationMethod := range verificationMethods {
		if err := m.keyStore.Delete(ctx, verificationMethod.ID.String()); err != nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("verification method '%s': %w", verificationMethod.ID, err))
		}
	}
	if len(deleteErrors) == 0 {
		return nil
	}
	return errors.Join(append([]error{errors.New("did:web DID deleted, but could not remove one or more private keys")}, deleteErrors...)...)
}

func (m Manager) RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error {
	return errors.New("RemoveVerificationMethod() is not yet supported for did:web")
}

func (m Manager) AddVerificationMethod(_ context.Context, _ did.DID, _ management.DIDKeyFlags) (*did.VerificationMethod, error) {
	return nil, errors.New("AddVerificationMethod() is not yet supported for did:web")
}

// Create creates a new did:web document.
func (m Manager) Create(ctx context.Context, opts management.CreationOptions) (*did.Document, crypto.Key, error) {
	var newDID *did.DID
	for _, opt := range opts.All() {
		if newDID != nil {
			return nil, nil, errors.New("multiple DID options provided")
		}
		switch option := opt.(type) {
		case userIDOption:
			// Make sure url config we use does not
			newDID, _ = URLToDID(*(m.baseURL).JoinPath(option.id))
		case didOption:
			// if it contains a user path, it must be in format did:web:<host>:iam:<user id>
			idParts := strings.Split(option.value.ID, ":")
			if (len(idParts) > 2 && (idParts[1] != "iam" || len(idParts) > 3)) ||
				// it must not contain empty path parts
				strings.HasSuffix(option.value.ID, ":") || strings.HasSuffix(option.value.ID, "::") {
				return nil, nil, errors.New("invalid user path in did:web DID, it must follow the pattern 'did:web:<host>:iam:<user id>'")
			}
			newDID = &option.value
		default:
			return nil, nil, fmt.Errorf("unknown option: %T", option)
		}
	}
	if newDID == nil {
		newDID, _ = URLToDID(*(m.baseURL).JoinPath(uuid.NewString()))
	}
	return m.create(ctx, *newDID)
}

func (m Manager) create(ctx context.Context, newDID did.DID) (*did.Document, crypto.Key, error) {
	// Check if it doesn't already exist. Otherwise, it fail later on (unique key constraint) but we might end up with an orphaned private key.
	exists, err := m.IsOwner(ctx, newDID)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		return nil, nil, management.ErrDIDAlreadyExists
	}

	verificationMethodKey, verificationMethod, err := m.createVerificationMethod(ctx, newDID)
	if err != nil {
		return nil, nil, err
	}
	if err := m.store.create(newDID, *verificationMethod); err != nil {
		return nil, nil, fmt.Errorf("store new DID: %w", err)
	}

	document := buildDocument(newDID, []did.VerificationMethod{*verificationMethod}, nil)
	return &document, verificationMethodKey, nil
}

func (m Manager) createVerificationMethod(ctx context.Context, ownerDID did.DID) (crypto.Key, *did.VerificationMethod, error) {
	verificationMethodID := did.DIDURL{
		DID:      ownerDID,
		Fragment: "0", // TODO: Which fragment should we use? Thumbprint, UUID, index, etc...
	}
	verificationMethodKey, err := m.keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
		return verificationMethodID.String(), nil
	})
	if err != nil {
		return nil, nil, err
	}
	verificationMethod, err := did.NewVerificationMethod(verificationMethodID, ssi.JsonWebKey2020, ownerDID, verificationMethodKey.Public())
	if err != nil {
		return nil, nil, err
	}
	return verificationMethodKey, verificationMethod, nil
}

// Resolve returns the did:web document for the given DID, if it is managed by this node.
func (m Manager) Resolve(id did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	vms, services, err := m.store.get(id)
	if err != nil {
		return nil, nil, err
	}
	document := buildDocument(id, vms, services)
	return &document, &resolver.DocumentMetadata{}, nil
}

func (m Manager) IsOwner(_ context.Context, id did.DID) (bool, error) {
	_, _, err := m.store.get(id)
	if errors.Is(err, resolver.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (m Manager) ListOwned(_ context.Context) ([]did.DID, error) {
	return m.store.list()
}

func (m Manager) CreateService(_ context.Context, subjectDID did.DID, service did.Service) (*did.Service, error) {
	if service.ID.String() == "" {
		// Generate random service ID
		serviceID := did.DIDURL{
			DID:      subjectDID,
			Fragment: uuid.NewString(),
		}
		service.ID = serviceID.URI()
	}
	err := m.store.createService(subjectDID, service)
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (m Manager) UpdateService(_ context.Context, subjectDID did.DID, serviceID ssi.URI, service did.Service) (*did.Service, error) {
	if service.ID.String() == "" {
		// ID not set in new version of the service, use the provided serviceID
		service.ID = serviceID
	}
	err := m.store.updateService(subjectDID, serviceID, service)
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (m Manager) DeleteService(_ context.Context, subjectDID did.DID, serviceID ssi.URI) error {
	return m.store.deleteService(subjectDID, serviceID)
}

func buildDocument(subject did.DID, verificationMethods []did.VerificationMethod, services []did.Service) did.Document {
	var vms []*did.VerificationMethod
	for _, verificationMethod := range verificationMethods {
		vms = append(vms, &verificationMethod)
	}

	document := did.Document{
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID:      subject,
		Service: services,
	}
	for _, verificationMethod := range verificationMethods {
		document.AddAssertionMethod(&verificationMethod)
		document.AddAuthenticationMethod(&verificationMethod)
		document.AddKeyAgreement(&verificationMethod)
		document.AddCapabilityDelegation(&verificationMethod)
		document.AddCapabilityInvocation(&verificationMethod)
	}
	return document
}
