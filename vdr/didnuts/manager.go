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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
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
func DefaultKeyFlags() didsubject.DIDKeyFlags {
	return didsubject.AssertionMethodUsage | didsubject.CapabilityInvocationUsage | didsubject.KeyAgreementUsage | didsubject.AuthenticationUsage | didsubject.CapabilityDelegationUsage
}

type keyFlagCreationOption didsubject.DIDKeyFlags

// KeyFlag specifies for what purposes the generated key can be used
func KeyFlag(flags didsubject.DIDKeyFlags) didsubject.CreationOption {
	return keyFlagCreationOption(flags)
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

// ErrInvalidOptions is returned when the given options have an invalid combination
var ErrInvalidOptions = errors.New("create request has invalid combination of options: SelfControl = true and CapabilityInvocation = false")

// Create creates a Nuts DID Document with a valid DID id based on a freshly generated keypair.
// The key is added to the verificationMethod list and referred to from the Authentication list
// It also publishes the DID Document to the network.
func (m Manager) Create(ctx context.Context, options didsubject.CreationOptions) (*did.Document, nutsCrypto.Key, error) {
	keyFlags, err := parseOptions(options)
	if err != nil {
		return nil, nil, err
	}

	if !keyFlags.Is(didsubject.CapabilityInvocationUsage) {
		return nil, nil, ErrInvalidOptions
	}

	doc, key, err := m.create(ctx, keyFlags)
	if err != nil {
		return nil, nil, err
	}
	if err := m.publish(ctx, *doc, key); err != nil {
		return nil, nil, err
	}

	// return the doc and the keyCreator that created the private key
	return doc, key, nil
}

// Deactivate updates the DID Document so it can no longer be updated
// It removes key material, services and controllers.
func (m Manager) Deactivate(ctx context.Context, id did.DID) error {
	// A deactivated DID resolves to an empty DID document.
	emptyDoc := CreateDocument()
	emptyDoc.ID = id
	return m.Update(ctx, id, emptyDoc)
}

func parseOptions(options didsubject.CreationOptions) (keyFlags didsubject.DIDKeyFlags, err error) {
	keyFlags = DefaultKeyFlags()
	for _, opt := range options.All() {
		switch o := opt.(type) {
		case keyFlagCreationOption:
			keyFlags = didsubject.DIDKeyFlags(o)
		default:
			return 0, fmt.Errorf("unknown option: %T", opt)
		}
	}
	return
}

func (m Manager) create(ctx context.Context, flags didsubject.DIDKeyFlags) (*did.Document, nutsCrypto.Key, error) {
	// First, generate a new keyPair with the correct kid
	// Currently, always keep the key in the keystore. This allows us to change the transaction format and regenerate transactions at a later moment.
	// Relevant issue:
	// https://github.com/nuts-foundation/nuts-node/issues/1947
	key, err := m.keyStore.New(ctx, DIDKIDNamingFunc)
	// } else {
	// 	key, err = nutsCrypto.NewEphemeralKey(didKIDNamingFunc)
	// }
	if err != nil {
		return nil, nil, err
	}

	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, nil, err
	}

	// Create the bare document. The Document DID will be the keyIDStr without the fragment.
	didID, _ := resolver.GetDIDFromURL(key.KID())
	doc := CreateDocument()
	doc.ID = didID

	var verificationMethod *did.VerificationMethod

	// Add VerificationMethod using generated key
	verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
	if err != nil {
		return nil, nil, err
	}

	applyKeyUsage(&doc, verificationMethod, flags)
	return &doc, key, nil
}

func (m Manager) publish(ctx context.Context, doc did.Document, key nutsCrypto.Key) error {
	payload, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	// extract the transaction refs from the controller metadata
	refs := make([]hash.SHA256Hash, 0)

	tx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
	dagTx, err := m.networkClient.CreateTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("could not store DID document in network: %w", err)
	}

	// add it to the store after the transaction is successful
	if err = m.store.Add(doc, didnutsStore.Transaction{
		Clock:       dagTx.Clock(),
		PayloadHash: dagTx.PayloadHash(),
		Previous:    dagTx.Previous(),
		Ref:         dagTx.Ref(),
		SigningTime: dagTx.SigningTime(),
	}); err != nil {
		return fmt.Errorf("DID document created but could not add result to store: %w", err)
	}

	return nil
}

// applyKeyUsage checks intendedKeyUsage and adds the given verificationMethod to every relationship specified as key usage.
func applyKeyUsage(document *did.Document, keyToAdd *did.VerificationMethod, intendedKeyUsage didsubject.DIDKeyFlags) {
	if intendedKeyUsage.Is(didsubject.CapabilityDelegationUsage) {
		document.AddCapabilityDelegation(keyToAdd)
	}
	if intendedKeyUsage.Is(didsubject.CapabilityInvocationUsage) {
		document.AddCapabilityInvocation(keyToAdd)
	}
	if intendedKeyUsage.Is(didsubject.AuthenticationUsage) {
		document.AddAuthenticationMethod(keyToAdd)
	}
	if intendedKeyUsage.Is(didsubject.AssertionMethodUsage) {
		document.AddAssertionMethod(keyToAdd)
	}
	if intendedKeyUsage.Is(didsubject.KeyAgreementUsage) {
		document.AddKeyAgreement(keyToAdd)
	}
}

// AddVerificationMethod adds a new key as a VerificationMethod to the document.
// The key is added to the VerficationMethod relationships specified by keyUsage.
func (m Manager) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage didsubject.DIDKeyFlags) (*did.VerificationMethod, error) {
	doc, meta, err := m.resolver.Resolve(id, &resolver.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return nil, err
	}
	if meta.Deactivated {
		return nil, resolver.ErrDeactivated
	}
	method, err := CreateNewVerificationMethodForDID(ctx, doc.ID, m.keyStore)
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

	controller, key, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
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

	tx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
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
	_, meta, err := m.store.Resolve(change.DID(), &resolver.ResolveMetadata{AllowDeactivated: true})
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

// Loop requires no implementation for the DIDWeb method manager.
func (m Manager) Loop(_ context.Context) {

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

func (m Manager) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, nutsCrypto.Key, error) {
	controllers, err := ResolveControllers(m.store, doc, nil)
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
