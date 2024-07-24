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
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/storage"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	didnutsStore "github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/util"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
)

var _ didsubject.MethodManager = (*Manager)(nil)
var _ didsubject.DocumentManager = (*Manager)(nil)

// NewManager creates a new Manager instance.
func NewManager(cryptoClient nutsCrypto.KeyStore, networkClient network.Transactions,
	didStore didnutsStore.Store, didResolver resolver.DIDResolver, DB *gorm.DB) *Manager {
	return &Manager{
		networkClient:   networkClient,
		db:              DB,
		store:           didStore,
		keyStore:        cryptoClient,
		resolver:        didResolver,
		serviceResolver: resolver.DIDServiceResolver{Resolver: didResolver},
	}
}

type Manager struct {
	db              *gorm.DB
	keyStore        nutsCrypto.KeyStore
	networkClient   network.Transactions
	resolver        resolver.DIDResolver
	serviceResolver resolver.ServiceResolver
	store           didnutsStore.Store
}

// MethodName is the DID method name used by Nuts
const MethodName = "nuts"

// CreateDocument creates an empty DID document with baseline properties set.
func CreateDocument() did.Document {
	return did.Document{
		Context: []interface{}{jsonld.JWS2020ContextV1URI(), did.DIDContextV1URI()},
	}
}

// DefaultKeyFlags returns the default DIDKeyFlags when creating did:nuts DIDs.
func DefaultKeyFlags() orm.DIDKeyFlags {
	return orm.AssertionKeyUsage() | orm.EncryptionKeyUsage()
}

// DIDKIDNamingFunc is a function used to name a key used in newly generated DID Documents.
func DIDKIDNamingFunc(pKey crypto.PublicKey) (string, error) {
	return getKIDName(pKey, nutsCrypto.Thumbprint)
}

// didSubKIDNamingFunc returns a KIDNamingFunc that can be used as param in the keyStore.New function.
// It wraps the KIDNamingFunc with the context of the DID of the document.
// It returns a keyID in the form of the documents DID with the new keys thumbprint as fragment.
// E.g. for a assertionMethod key that differs from the key the DID document was created with.
func didSubKIDNamingFunc(owningDID did.DID) nutsCrypto.KIDNamingFunc {
	return func(pKey crypto.PublicKey) (string, error) {
		return getKIDName(pKey, func(_ jwk.Key) (string, error) {
			return owningDID.ID, nil
		})
	}
}

func getKIDName(pKey crypto.PublicKey, idFunc func(key jwk.Key) (string, error)) (string, error) {
	// according to RFC006:
	// --------------------

	// generate idString
	jwKey, err := jwk.FromRaw(pKey)
	if err != nil {
		return "", fmt.Errorf("could not generate kid: %w", err)
	}

	idString, err := idFunc(jwKey)
	if err != nil {
		return "", err
	}

	// generate kid fragment
	err = jwk.AssignKeyID(jwKey)
	if err != nil {
		return "", err
	}

	// assemble
	kid := &did.DIDURL{}
	kid.Method = MethodName
	kid.ID = idString
	kid.Fragment = jwKey.KeyID()

	return kid.String(), nil
}

// Deactivate updates the DID Document so it can no longer be updated
// It removes key material, services and controllers.
func (m Manager) Deactivate(ctx context.Context, id did.DID) error {
	// A deactivated DID resolves to an empty DID document.
	emptyDoc := CreateDocument()
	emptyDoc.ID = id
	return m.Update(ctx, id, emptyDoc)
}

// RemoveVerificationMethod is a helper function to remove a verificationMethod from a DID Document
func (m Manager) RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error {
	doc, _, err := m.resolver.Resolve(id, &resolver.ResolveMetadata{AllowDeactivated: true})
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
func CreateNewVerificationMethodForDID(ctx context.Context, id did.DID, keyCreator nutsCrypto.KeyCreator) (*did.VerificationMethod, error) {
	keyRef, publicKey, err := keyCreator.New(ctx, didSubKIDNamingFunc(id))
	if err != nil {
		return nil, err
	}
	keyID, err := did.ParseDIDURL(keyRef.KID)
	if err != nil {
		return nil, err
	}
	method, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, id, publicKey)
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

	currentDIDDocument, currentMeta, err := m.store.Resolve(id, resolverMetadata)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}
	if currentMeta.Deactivated {
		return fmt.Errorf("update DID document: %w", resolver.ErrDeactivated)
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, did.DIDContextV1URI())
	next = withJSONLDContext(next, jsonld.JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	if err = ManagedDocumentValidator(m.serviceResolver).Validate(next); err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	controller, kid, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// for the metadata
	_, controllerMeta, err := m.resolver.Resolve(controller.ID, nil)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(DIDDocumentType, payload, kid).WithAdditionalPrevs(previousTransactions)
	dagTx, err := m.networkClient.CreateTransaction(ctx, tx)
	if err != nil {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, nutsCrypto.ErrPrivateKeyNotFound) {
			err = resolver.ErrDIDNotManagedByThisNode
		}
		return fmt.Errorf("update DID document: %w", err)
	}

	// add it to the store after the transaction is successful
	if err = m.store.Add(next, didnutsStore.Transaction{
		Clock:       dagTx.Clock(),
		PayloadHash: dagTx.PayloadHash(),
		Previous:    dagTx.Previous(),
		Ref:         dagTx.Ref(),
		SigningTime: dagTx.SigningTime(),
	}); err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldDID, id).
		Info("DID Document updated")

	return nil
}

/******************************
 * New style DID Method Manager
 ******************************/

func (m Manager) NewDocument(ctx context.Context, _ orm.DIDKeyFlags) (*orm.DIDDocument, error) {
	keyRef, publicKey, err := m.keyStore.New(ctx, DIDKIDNamingFunc)
	if err != nil {
		return nil, err
	}
	keyFlags := DefaultKeyFlags()

	keyID, err := did.ParseDIDURL(keyRef.KID)
	if err != nil {
		return nil, err
	}

	var verificationMethod *did.VerificationMethod
	// Add VerificationMethod using generated key
	verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, keyID.DID, publicKey)
	if err != nil {
		return nil, err
	}
	vmAsJson, _ := json.Marshal(verificationMethod)
	now := time.Now().Unix()
	sqlDoc := orm.DIDDocument{
		DID: orm.DID{
			ID: keyID.DID.String(),
		},
		CreatedAt: now,
		UpdatedAt: now,
		VerificationMethods: []orm.VerificationMethod{
			{
				ID:       verificationMethod.ID.String(),
				KeyTypes: orm.VerificationMethodKeyType(keyFlags),
				Data:     vmAsJson,
			},
		},
	}

	return &sqlDoc, nil
}

func (m Manager) NewVerificationMethod(ctx context.Context, id did.DID, _ orm.DIDKeyFlags) (*did.VerificationMethod, error) {
	// did:nuts uses EC keys for everything, so it doesn't use the DIDKeyFlags
	return CreateNewVerificationMethodForDID(ctx, id, m.keyStore)
}

func (m Manager) Commit(ctx context.Context, change orm.DIDChangeLog) error {
	var err error
	switch change.Type {
	case orm.DIDChangeCreated:
		err = m.onCreate(ctx, change)
	case orm.DIDChangeDeactivated:
		err = m.onDeactivate(ctx, change)
	case orm.DIDChangeUpdated:
		err = m.onUpdate(ctx, change)
	default:
		err = fmt.Errorf("unknown event type: %s", change.Type)
	}
	return err
}

func (m Manager) IsCommitted(_ context.Context, change orm.DIDChangeLog) (bool, error) {
	// get the latest from the didStore
	_, meta, err := m.store.Resolve(change.DID(), &resolver.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return false, err
	}
	changeHash := hash.SHA256Sum([]byte(change.DIDDocumentVersion.Raw))
	return meta.Hash.Equals(changeHash), nil
}

func (m Manager) onCreate(ctx context.Context, event orm.DIDChangeLog) error {
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
		publicKey, err := didDocument.VerificationMethod[0].PublicKey()
		if err != nil {
			return err
		}
		networkTx := network.TransactionTemplate(DIDDocumentType, payload, didDocument.VerificationMethod[0].ID.String()).WithAttachKey(publicKey).WithAdditionalPrevs(refs)
		// set transaction on context
		transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
		_, err = m.networkClient.CreateTransaction(transactionContext, networkTx)
		if err != nil {
			return fmt.Errorf("could not publish DID document on the network: %w", err)
		}
		return nil
	})
}

func (m Manager) onUpdate(ctx context.Context, event orm.DIDChangeLog) error {
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

	controller, kid, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
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

	networkTransaction := network.TransactionTemplate(DIDDocumentType, payload, kid).WithAdditionalPrevs(previousTransactions)
	_, err = m.networkClient.CreateTransaction(ctx, networkTransaction)
	return err
}

func (m Manager) onDeactivate(ctx context.Context, event orm.DIDChangeLog) error {
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

func (c cryptoKey) KeyName() string {
	panic("implement me")
}

func (c cryptoKey) Version() string {
	panic("implement me")
}

func withJSONLDContext(document did.Document, ctx ssi.URI) did.Document {
	contextPresent := false

	for _, c := range document.Context {
		if util.LDContextToString(c) == ctx.String() {
			contextPresent = true
		}
	}

	if !contextPresent {
		document.Context = append(document.Context, ctx)
	}
	return document
}

func (m Manager) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, string, error) {
	controllers, err := ResolveControllers(m.store, doc, nil)
	if err != nil {
		return did.Document{}, "", fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, "", fmt.Errorf("could not find any controllers for document")
	}

	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			ok, err := m.keyStore.Exists(ctx, cik.ID.String())
			if err == nil && ok {
				return c, cik.ID.String(), nil
			}
		}
	}

	return did.Document{}, "", fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}
