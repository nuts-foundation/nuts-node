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
	"crypto"
	"encoding/json"
	"fmt"
	didnutsStore "github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
)

var _ didsubject.MethodManager = (*Manager)(nil)

// NewManager creates a new Manager instance.
func NewManager(DB *gorm.DB, cryptoClient nutsCrypto.KeyStore, networkClient network.Transactions, didStore didnutsStore.Store, didResolver resolver.DIDResolver,
	// deprecated
	creator management.DocCreator, owner management.DocumentOwner) *Manager {
	return &Manager{
		db:            DB,
		keyStore:      cryptoClient,
		networkClient: networkClient,
		resolver:      didResolver,
		Store:         didStore,
		// deprecated
		creator:       creator,
		documentOwner: owner,
	}
}

var _ management.DocumentManager = (*Manager)(nil)

type Manager struct {
	db            *gorm.DB
	keyStore      nutsCrypto.KeyStore
	networkClient network.Transactions
	resolver      resolver.DIDResolver
	Store         didnutsStore.Store

	// deprecated
	creator       management.DocCreator
	documentOwner management.DocumentOwner
	manipulator   management.DocManipulator
}

func (m Manager) Deactivate(ctx context.Context, id did.DID) error {
	return m.manipulator.Deactivate(ctx, id)
}

func (m Manager) Create(ctx context.Context, options management.CreationOptions) (*did.Document, nutsCrypto.Key, error) {
	return m.creator.Create(ctx, options)
}

func (m Manager) Resolve(_ did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	return nil, nil, fmt.Errorf("Resolve() is not supported for did:%s", MethodName)
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

func (m Manager) NewDocument(ctx context.Context, keyFlags didsubject.DIDKeyFlags) (*didsubject.DIDDocument, error) {
	// First, generate a new keyPair with the correct kid
	// Currently, always keep the key in the keystore. This allows us to change the transaction format and regenerate transactions at a later moment.
	// Relevant issue:
	// https://github.com/nuts-foundation/nuts-node/issues/1947
	key, err := m.keyStore.New(ctx, DIDKIDNamingFunc)
	if err != nil {
		return nil, err
	}

	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, err
	}

	didID, _ := resolver.GetDIDFromURL(key.KID())
	var verificationMethod *did.VerificationMethod
	// Add VerificationMethod using generated key
	verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, didID, key.Public())
	if err != nil {
		return nil, err
	}
	vmAsJson, _ := json.Marshal(verificationMethod)
	now := time.Now().Unix()
	sqlDoc := didsubject.DIDDocument{
		DID: didsubject.DID{
			ID: didID.String(),
		},
		CreatedAt: now,
		UpdatedAt: now,
		VerificationMethods: []didsubject.VerificationMethod{
			{
				ID:       verificationMethod.ID.String(),
				KeyTypes: didsubject.VerificationMethodKeyType(keyFlags),
				Data:     vmAsJson,
			},
		},
	}

	return &sqlDoc, nil
}

func (m Manager) NewVerificationMethod(ctx context.Context, id did.DID, _ didsubject.DIDKeyFlags) (*did.VerificationMethod, error) {
	// did:nuts uses EC keys for everything, so it doesn't use the DIDKeyFlags
	return CreateNewVerificationMethodForDID(ctx, id, m.keyStore)
}

func (m Manager) Commit(ctx context.Context, change didsubject.DIDChangeLog) error {
	var err error
	switch change.Type {
	case didsubject.DIDChangeCreated:
		err = m.onCreate(ctx, change)
	case didsubject.DIDChangeDeactivated:
		err = m.onDeactivate(ctx, change)
	case didsubject.DIDChangeUpdated:
		err = m.onUpdate(ctx, change)
	default:
		err = fmt.Errorf("unknown event type: %s", change.Type)
	}
	return err
}

func (m Manager) IsCommitted(_ context.Context, change didsubject.DIDChangeLog) (bool, error) {
	// get the latest from the didStore
	_, meta, err := m.Store.Resolve(change.DID(), &resolver.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return false, err
	}
	changeHash := hash.SHA256Sum([]byte(change.DIDDocumentVersion.Raw))
	return meta.Hash.Equals(changeHash), nil
}

func (m Manager) onCreate(ctx context.Context, event didsubject.DIDChangeLog) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		didDocument, err := event.DIDDocumentVersion.ToDIDDocument()
		if err != nil {
			return err
		}
		// publish
		payload, err := json.Marshal(didDocument)
		if err != nil {
			return err
		}

		// extract the transaction refs from the controller metadata
		refs := make([]hash.SHA256Hash, 0)
		key := cryptoKey{vm: *didDocument.VerificationMethod[0]}
		networkTx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
		_, err = m.networkClient.CreateTransaction(ctx, networkTx)
		if err != nil {
			return fmt.Errorf("could not publish DID document on the network: %w", err)
		}
		return nil
	})
}

func (m Manager) onUpdate(ctx context.Context, event didsubject.DIDChangeLog) error {
	id := event.DID()
	resolverMetadata := &resolver.ResolveMetadata{
		AllowDeactivated: true,
	}

	currentDIDDocument, currentMeta, err := m.resolver.Resolve(id, resolverMetadata)
	if err != nil {
		return err
	}
	if resolver.IsDeactivated(*currentDIDDocument) {
		// should not occur
		// we're not using the deactivated flag in the resolver metadata since there could be conflicted docs
		log.Logger().Warnf("document (%s) is deactivated, won't update", currentDIDDocument.ID.String())
		return nil
	}
	next, err := event.DIDDocumentVersion.ToDIDDocument()
	if err != nil {
		return err
	}

	// Validate document. No more changes should be made to the document after this point.
	serviceResolver := resolver.DIDServiceResolver{Resolver: m.resolver}
	if err = ManagedDocumentValidator(serviceResolver).Validate(next); err != nil {
		return err
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	controller, key, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		return err
	}

	// for the metadata
	_, controllerMeta, err := m.resolver.Resolve(controller.ID, nil)
	if err != nil {
		return err
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	networkTransaction := network.TransactionTemplate(DIDDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = m.networkClient.CreateTransaction(ctx, networkTransaction)
	return err
}

func (m Manager) onDeactivate(ctx context.Context, event didsubject.DIDChangeLog) error {
	return m.Deactivate(ctx, event.DID())
}

type cryptoKey struct {
	vm did.VerificationMethod
}

func (c cryptoKey) KID() string {
	return c.vm.ID.String()
}

func (c cryptoKey) Public() crypto.PublicKey {
	pk, _ := c.vm.PublicKey()
	return pk
}

func (m Manager) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, nutsCrypto.Key, error) {
	controllers, err := ResolveControllers(m.Store, doc, nil)
	if err != nil {
		return did.Document{}, nil, fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, nil, fmt.Errorf("could not find any controllers for document")
	}

	var key nutsCrypto.Key
	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			key, err = m.keyStore.Resolve(ctx, cik.ID.String())
			if err == nil {
				return c, key, nil
			}
		}
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}
