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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/nuts-foundation/nuts-node/vdr/sql"
	"gorm.io/gorm"
)

func DefaultCreationOptions() management.CreationOptions {
	return management.Create(MethodName)
}

type rootDIDOption struct{}

// RootDID is an option to set the DID for the did:web document.
func RootDID() management.CreationOption {
	return rootDIDOption{}
}

var _ management.DocumentManager = (*Manager)(nil)

// NewManager creates a new Manager to create and update did:web DID documents.
func NewManager(rootDID did.DID, tenantPath string, keyStore crypto.KeyStore, db *gorm.DB) *Manager {
	return &Manager{
		db:         db,
		rootDID:    rootDID,
		tenantPath: tenantPath,
		keyStore:   keyStore,
	}
}

// Manager creates and updates did:web documents
type Manager struct {
	db         *gorm.DB
	rootDID    did.DID
	keyStore   crypto.KeyStore
	tenantPath string
}

func (m Manager) Deactivate(ctx context.Context, subjectDID did.DID) error {
	var err error
	var sqlDocument *sql.DIDDocument
	err = m.db.Transaction(func(tx *gorm.DB) error {
		didStore := sql.NewDIDManager(tx)
		documentStore := sql.NewDIDDocumentManager(tx)
		sqlDocument, err = documentStore.Latest(subjectDID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return resolver.ErrNotFound
			}
			return err
		}
		return didStore.Delete(subjectDID)
	})
	if err != nil {
		return err
	}
	var deleteErrors []error
	for _, verificationMethod := range sqlDocument.VerificationMethods {
		if err := m.keyStore.Delete(ctx, verificationMethod.ID); err != nil {
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
	var err error
	for _, opt := range opts.All() {
		switch opt.(type) {
		case rootDIDOption:
			newDID = &m.rootDID
		default:
			return nil, nil, fmt.Errorf("unknown option: %T", opt)
		}
	}
	if newDID == nil {
		newDID, err = did.ParseDID(fmt.Sprintf("%s:iam:%s", m.rootDID.String(), uuid.NewString()))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse new DID: %w", err)
	}
	var document did.Document
	var verificationMethodKey crypto.Key
	err = m.db.Transaction(func(tx *gorm.DB) error {
		var verificationMethod *did.VerificationMethod
		documentStore := sql.NewDIDDocumentManager(tx)

		_, err = documentStore.Latest(*newDID)
		if err == nil {
			return management.ErrDIDAlreadyExists
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		verificationMethodKey, verificationMethod, err = m.createVerificationMethod(ctx, *newDID)
		if err != nil {
			return err
		}
		vmAsJson, err := json.Marshal(verificationMethod)
		if err != nil {
			return err
		}

		sqlDid := sql.DID{
			ID:      newDID.String(),
			Subject: newDID.String(), // todo pass through options
		}
		var doc *sql.DIDDocument
		if doc, err = documentStore.CreateOrUpdate(sqlDid, []sql.SqlVerificationMethod{{
			ID:            verificationMethod.ID.String(),
			DIDDocumentID: sqlDid.ID,
			KeyTypes:      sql.VerificationMethodKeyType(management.AssertionMethodUsage | management.AuthenticationUsage | management.CapabilityDelegationUsage | management.CapabilityInvocationUsage), // todo pass via options
			Data:          vmAsJson,
		}}, nil); err != nil {
			return fmt.Errorf("store new DID document: %w", err)
		}

		document, err = buildDocument(*newDID, *doc)
		return err
	})

	return &document, verificationMethodKey, err
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
	didDocumentMananager := sql.NewDIDDocumentManager(m.db)

	doc, err := didDocumentMananager.Latest(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, resolver.ErrNotFound
		}
		return nil, nil, err
	}
	document, err := buildDocument(id, *doc)
	return &document, &resolver.DocumentMetadata{}, err
}

func (m Manager) CreateService(_ context.Context, subjectDID did.DID, service did.Service) (*did.Service, error) {
	var err error
	var added *did.Service
	err = m.db.Transaction(func(tx *gorm.DB) error {
		added, err = m.createService(tx, subjectDID, service)
		return err
	})

	return added, err
}

func (m Manager) createService(tx *gorm.DB, subjectDID did.DID, service did.Service) (*did.Service, error) {
	didDocumentManager := sql.NewDIDDocumentManager(tx)

	current, err := didDocumentManager.Latest(subjectDID)
	if err != nil {
		return nil, err
	}

	if service.ID.String() == "" {
		// Generate random service ID
		serviceID := did.DIDURL{
			DID:      subjectDID,
			Fragment: uuid.NewString(),
		}
		service.ID = serviceID.URI()
	}
	asJson, err := json.Marshal(service)
	if err != nil {
		return nil, err
	}
	sqlService := sql.SqlService{
		ID:            service.ID.String(),
		DIDDocumentID: current.DidID,
		Data:          asJson,
	}

	_, err = didDocumentManager.CreateOrUpdate(current.DID, current.VerificationMethods, append(current.Services, sqlService))

	return &service, err
}

func (m Manager) UpdateService(_ context.Context, subjectDID did.DID, serviceID ssi.URI, service did.Service) (*did.Service, error) {
	if service.ID.String() == "" {
		// ID not set in new version of the service, use the provided serviceID
		service.ID = serviceID
	}
	var added *did.Service
	err := m.db.Transaction(func(tx *gorm.DB) error {
		// first delete
		err := m.deleteService(tx, subjectDID, serviceID)
		if err != nil {
			return err
		}
		// then add
		added, err = m.createService(tx, subjectDID, service)
		return err
	})

	//commit and return
	return added, err
}

func (m Manager) DeleteService(_ context.Context, subjectDID did.DID, serviceID ssi.URI) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		return m.deleteService(tx, subjectDID, serviceID)
	})
}

func (m Manager) deleteService(tx *gorm.DB, subjectDID did.DID, serviceID ssi.URI) error {
	didDocumentManager := sql.NewDIDDocumentManager(tx)

	current, err := didDocumentManager.Latest(subjectDID)
	if err != nil {
		return err
	}

	services := current.Services
	j := 0
	for i, s := range services {
		if s.ID == serviceID.String() {
			continue
		}
		services[j] = services[i]
		j++
	}
	services = services[:j]
	_, err = didDocumentManager.CreateOrUpdate(current.DID, current.VerificationMethods, services)

	return err
}

func buildDocument(newDID did.DID, doc sql.DIDDocument) (did.Document, error) {
	document := did.Document{
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID: newDID,
	}
	for _, sqlVM := range doc.VerificationMethods {
		verificationMethod := did.VerificationMethod{}
		err := json.Unmarshal(sqlVM.Data, &verificationMethod)
		if err != nil {
			return document, err
		}

		if sqlVM.KeyTypes&sql.VerificationMethodKeyType(management.AssertionMethodUsage) != 0 {
			document.AddAssertionMethod(&verificationMethod)
		}
		if sqlVM.KeyTypes&sql.VerificationMethodKeyType(management.AuthenticationUsage) != 0 {
			document.AddAuthenticationMethod(&verificationMethod)
		}
		if sqlVM.KeyTypes&sql.VerificationMethodKeyType(management.KeyAgreementUsage) != 0 {
			document.AddKeyAgreement(&verificationMethod)
		}
		if sqlVM.KeyTypes&sql.VerificationMethodKeyType(management.CapabilityDelegationUsage) != 0 {
			document.AddCapabilityDelegation(&verificationMethod)
		}
		if sqlVM.KeyTypes&sql.VerificationMethodKeyType(management.CapabilityInvocationUsage) != 0 {
			document.AddCapabilityInvocation(&verificationMethod)
		}
	}
	for _, sqlService := range doc.Services {
		service := did.Service{}
		err := json.Unmarshal(sqlService.Data, &service)
		if err != nil {
			return document, err
		}
		document.Service = append(document.Service, service)
	}

	return document, nil
}
