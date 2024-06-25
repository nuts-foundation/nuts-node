/*
 * Copyright (C) 2024 Nuts community
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

package didnuts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	didnutsStore "github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
)

// NewManager creates a new Manager instance.
func NewManager(cryptoClient crypto.KeyStore, networkClient network.Transactions,
	didStore didnutsStore.Store, didResolver resolver.DIDResolver, DB *gorm.DB) *Manager {
	return &Manager{
		NetworkClient:   networkClient,
		DB:              DB,
		Store:           didStore,
		KeyStore:        cryptoClient,
		Resolver:        didResolver,
		ServiceResolver: resolver.DIDServiceResolver{Resolver: didResolver},
	}
}

var _ management.DocumentManager = (*Manager)(nil)

type Manager struct {
	NetworkClient   network.Transactions
	DB              *gorm.DB
	Store           didnutsStore.Store
	KeyStore        crypto.KeyStore
	Resolver        resolver.DIDResolver
	ServiceResolver resolver.ServiceResolver
}

func (m Manager) CreateService(_ context.Context, _ did.DID, _ did.Service) (*did.Service, error) {
	return nil, fmt.Errorf("CreateService() is not supported for did:%s", MethodName)
}

func (m Manager) UpdateService(_ context.Context, _ did.DID, _ ssi.URI, _ did.Service) (*did.Service, error) {
	return nil, fmt.Errorf("UpdateService() is not supported for did:%s", MethodName)
}

func (m Manager) DeleteService(_ context.Context, _ did.DID, _ ssi.URI) error {
	return fmt.Errorf("DeleteService() is not supported for did:%s", MethodName)
}

// AddVerificationMethod adds a new key as a VerificationMethod to the document.
// The key is added to the VerficationMethod relationships specified by keyUsage.
func (m Manager) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage management.DIDKeyFlags) (*did.VerificationMethod, error) {
	doc, meta, err := m.Resolver.Resolve(id, &resolver.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return nil, err
	}
	if meta.Deactivated {
		return nil, resolver.ErrDeactivated
	}
	method, err := CreateNewVerificationMethodForDID(ctx, doc.ID, m.KeyStore)
	if err != nil {
		return nil, err
	}
	method.Controller = doc.ID
	doc.VerificationMethod.Add(method)
	applyKeyUsage(doc, method, keyUsage)
	if err = m.Update(ctx, id, *doc); err != nil {
		return nil, err
	}
	return method, nil
}

// RemoveVerificationMethod is a helper function to remove a verificationMethod from a DID Document
func (m Manager) RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error {
	doc, _, err := m.Resolver.Resolve(id, &resolver.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	lenBefore := len(doc.VerificationMethod)
	doc.RemoveVerificationMethod(keyID)
	if lenBefore == len(doc.VerificationMethod) {
		// do not update if nothing has changed
		return nil
	}

	return m.Update(ctx, id, *doc)
}

// CreateNewVerificationMethodForDID creates a new VerificationMethod of type JsonWebKey2020
// with a freshly generated key for a given DID.
func CreateNewVerificationMethodForDID(ctx context.Context, id did.DID, keyCreator crypto.KeyCreator) (*did.VerificationMethod, error) {
	key, err := keyCreator.New(ctx, didSubKIDNamingFunc(id))
	if err != nil {
		return nil, err
	}
	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, err
	}
	method, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, id, key.Public())
	if err != nil {
		return nil, err
	}
	return method, nil
}

// Update updates a DID Document based on the DID.
// It only works on did:nuts, so is subject for removal in the future.
func (m Manager) Update(ctx context.Context, id did.DID, next did.Document) error {
	log.Logger().
		WithField(core.LogFieldDID, id).
		Debug("Updating DID Document")
	resolverMetadata := &resolver.ResolveMetadata{
		AllowDeactivated: true,
	}

	currentDIDDocument, currentMeta, err := m.Store.Resolve(id, resolverMetadata)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}
	if currentMeta.Deactivated {
		return fmt.Errorf("update DID document: %w", resolver.ErrDeactivated)
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, did.DIDContextV1URI())
	next = withJSONLDContext(next, NutsDIDContextV1URI())
	next = withJSONLDContext(next, JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	if err = ManagedDocumentValidator(m.ServiceResolver).Validate(next); err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	controller, key, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// for the metadata
	_, controllerMeta, err := m.Resolver.Resolve(controller.ID, nil)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = m.NetworkClient.CreateTransaction(ctx, tx)
	if err != nil {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrPrivateKeyNotFound) {
			err = resolver.ErrDIDNotManagedByThisNode
		}
		return fmt.Errorf("update DID document: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldDID, id).
		Info("DID Document updated")

	return nil
}
