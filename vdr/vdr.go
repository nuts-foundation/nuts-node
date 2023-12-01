/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

// Package vdr contains a verifiable data registry to the w3c specification
// and provides primitives for storing and working with Nuts DID based identities.
// It provides an easy to work with web api and a command line interface.
// It provides underlying storage back ends to store, update and search for Nuts identities.
package vdr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didjwk"
	"github.com/nuts-foundation/nuts-node/vdr/didkey"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	didnutsStore "github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/util"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// ModuleName is the name of the engine
const ModuleName = "VDR"

var _ VDR = (*Module)(nil)
var _ core.Named = (*Module)(nil)
var _ core.Configurable = (*Module)(nil)

// Module implements VDR, which stands for the Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type Module struct {
	store             didnutsStore.Store
	network           network.Transactions
	networkAmbassador didnuts.Ambassador
	creators          map[string]management.DocCreator
	managedResolvers  map[string]resolver.DIDResolver
	documentOwners    map[string]management.DocumentOwner
	didResolver       *resolver.DIDResolverRouter
	serviceResolver   resolver.ServiceResolver
	keyStore          crypto.KeyStore
	storageInstance   storage.Engine
	eventManager      events.Event
}

// ResolveManaged resolves a DID document that is managed by the local node.
func (r *Module) ResolveManaged(id did.DID) (*did.Document, error) {
	managedResolver := r.managedResolvers[id.Method]
	if managedResolver == nil {
		return nil, fmt.Errorf("unsupported method: %s", id.Method)
	}
	document, _, err := managedResolver.Resolve(id, nil)
	return document, err
}

func (r *Module) Resolver() resolver.DIDResolver {
	return r.didResolver
}

// NewVDR creates a new Module with provided params
func NewVDR(cryptoClient crypto.KeyStore, networkClient network.Transactions,
	didStore didnutsStore.Store, eventManager events.Event, storageInstance storage.Engine) *Module {
	didResolver := &resolver.DIDResolverRouter{}
	return &Module{
		network:         networkClient,
		eventManager:    eventManager,
		didResolver:     didResolver,
		store:           didStore,
		serviceResolver: resolver.DIDServiceResolver{Resolver: didResolver},
		keyStore:        cryptoClient,
		storageInstance: storageInstance,
	}
}

func (r *Module) Name() string {
	return ModuleName
}

// Configure configures the Module engine.
func (r *Module) Configure(config core.ServerConfig) error {
	r.networkAmbassador = didnuts.NewAmbassador(r.network, r.store, r.eventManager)

	// Register DID methods
	r.didResolver.Register(didnuts.MethodName, &didnuts.Resolver{Store: r.store})
	r.didResolver.Register(didweb.MethodName, didweb.NewResolver())
	r.didResolver.Register(didjwk.MethodName, didjwk.NewResolver())
	r.didResolver.Register(didkey.MethodName, didkey.NewResolver())

	r.creators = map[string]management.DocCreator{
		didnuts.MethodName: didnuts.Creator{KeyStore: r.keyStore},
	}
	r.documentOwners = map[string]management.DocumentOwner{
		didnuts.MethodName: newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: r.keyStore}, r.didResolver),
	}

	// Methods we can produce from the Nuts node
	publicURL, err := config.ServerURL()
	if err == nil {
		didwebManager := didweb.NewManager(*publicURL.JoinPath("iam"), r.keyStore, r.storageInstance.GetSQLDatabase())
		r.creators[didweb.MethodName] = didwebManager
		r.documentOwners[didweb.MethodName] = didwebManager
		r.managedResolvers = map[string]resolver.DIDResolver{
			didweb.MethodName: didwebManager,
		}
	}

	// Initiate the routines for auto-updating the data.
	r.networkAmbassador.Configure()
	return nil
}

func (r *Module) Start() error {
	err := r.networkAmbassador.Start()
	if err != nil {
		return err
	}

	// VDR migration needs to be started after ambassador has started!
	count, err := r.store.DocumentCount()
	if err != nil {
		return err
	}
	if count == 0 {
		// remove after v6 release
		_, err = r.network.Reprocess(context.Background(), "application/did+json")
	}

	return err
}

func (r *Module) Shutdown() error {
	return nil
}

func (r *Module) ConflictedDocuments() ([]did.Document, []resolver.DocumentMetadata, error) {
	conflictedDocs := make([]did.Document, 0)
	conflictedMeta := make([]resolver.DocumentMetadata, 0)

	err := r.store.Conflicted(func(doc did.Document, metadata resolver.DocumentMetadata) error {
		conflictedDocs = append(conflictedDocs, doc)
		conflictedMeta = append(conflictedMeta, metadata)
		return nil
	})
	return conflictedDocs, conflictedMeta, err
}

func (r *Module) IsOwner(ctx context.Context, id did.DID) (bool, error) {
	owner := r.documentOwners[id.Method]
	if owner == nil {
		return false, fmt.Errorf("unsupported method: %s", id.Method)
	}
	return owner.IsOwner(ctx, id)
}

func (r *Module) ListOwned(ctx context.Context) ([]did.DID, error) {
	var results []did.DID
	for _, owner := range r.documentOwners {
		owned, err := owner.ListOwned(ctx)
		if err != nil {
			return nil, err
		}
		results = append(results, owned...)
	}
	return results, nil
}

// newOwnConflictedDocIterator accepts two counters and returns a new DocIterator that counts the total number of
// conflicted documents, both total and owned by this node.
func (r *Module) newOwnConflictedDocIterator(totalCount, ownedCount *int) management.DocIterator {
	return func(doc did.Document, metadata resolver.DocumentMetadata) error {
		*totalCount++
		controllers, err := didnuts.ResolveControllers(r.store, doc, nil)
		if err != nil {
			log.Logger().
				WithField(core.LogFieldDID, doc.ID).
				WithError(err).
				Info("failed to resolve controller of conflicted DID document")
			return nil
		}
		for _, controller := range controllers {
			// TODO: Fix context.TODO() when we have a context in the Diagnostics() method
			isOwned, err := r.IsOwner(context.TODO(), controller.ID)
			if err != nil {
				log.Logger().
					WithField(core.LogFieldDID, controller.ID).
					WithError(err).
					Info("failed to check ownership of conflicted DID document")
			}
			if isOwned {
				*ownedCount++
			}
		}
		return nil
	}
}

// Diagnostics returns the diagnostics for this engine
func (r *Module) Diagnostics() []core.DiagnosticResult {
	// return # conflicted docs
	totalCount := 0
	ownedCount := 0

	// uses dedicated storage shelf for conflicted docs, does not loop over all documents
	err := r.store.Conflicted(r.newOwnConflictedDocIterator(&totalCount, &ownedCount))
	if err != nil {
		log.Logger().Errorf("Failed to resolve conflicted documents diagnostics: %v", err)
	}

	docCount, _ := r.store.DocumentCount()

	// to go from int+error to interface{}
	countOrError := func(count int, err error) interface{} {
		if err != nil {
			return "error"
		}
		return count
	}

	return []core.DiagnosticResult{
		core.DiagnosticResultMap{
			Title: "conflicted_did_documents",
			Items: []core.DiagnosticResult{
				&core.GenericDiagnosticResult{
					Title:   "total_count",
					Outcome: countOrError(totalCount, err),
				},
				&core.GenericDiagnosticResult{
					Title:   "owned_count",
					Outcome: countOrError(ownedCount, err),
				},
			},
		},
		&core.GenericDiagnosticResult{
			Title:   "did_documents_count",
			Outcome: docCount,
		},
	}
}

// Create generates a new DID Document
func (r *Module) Create(ctx context.Context, method string, options management.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	log.Logger().Debug("Creating new DID Document.")

	// for all controllers given in the options, we need to capture the metadata so the new transaction can reference to it
	// holder for all metadata of the controllers
	controllerMetadata := make([]resolver.DocumentMetadata, len(options.Controllers))

	// if any controllers have been added, check if they exist through the didResolver
	if len(options.Controllers) > 0 {
		for _, controller := range options.Controllers {
			_, meta, err := r.didResolver.Resolve(controller, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("could not create DID document: could not resolve a controller: %w", err)
			}
			controllerMetadata = append(controllerMetadata, *meta)
		}
	}

	creator := r.creators[method]
	if creator == nil {
		return nil, nil, fmt.Errorf("unsupported method: %s", method)
	}
	doc, key, err := creator.Create(ctx, options)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create DID document (method %s): %w", method, err)
	}

	if method == didnuts.MethodName {
		payload, err := json.Marshal(doc)
		if err != nil {
			return nil, nil, err
		}

		// extract the transaction refs from the controller metadata
		refs := make([]hash.SHA256Hash, 0)
		for _, meta := range controllerMetadata {
			refs = append(refs, meta.SourceTransactions...)
		}

		tx := network.TransactionTemplate(didnuts.DIDDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
		_, err = r.network.CreateTransaction(ctx, tx)
		if err != nil {
			return nil, nil, fmt.Errorf("could not store DID document in network: %w", err)
		}
	}

	log.Logger().
		WithField(core.LogFieldDID, doc.ID).
		Info("New DID Document created")

	return doc, key, nil
}

// Update updates a DID Document based on the DID
func (r *Module) Update(ctx context.Context, id did.DID, next did.Document) error {
	log.Logger().
		WithField(core.LogFieldDID, id).
		Debug("Updating DID Document")
	resolverMetadata := &resolver.ResolveMetadata{
		AllowDeactivated: true,
	}

	// Since the update mechanism is "did:nuts"-specific, we can't accidentally update a non-"did:nuts" document,
	// but check it defensively to avoid obscure errors later.
	if id.Method != didnuts.MethodName {
		return fmt.Errorf("can't update DID document of type: %s", id.Method)
	}

	currentDIDDocument, currentMeta, err := r.store.Resolve(id, resolverMetadata)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}
	if resolver.IsDeactivated(*currentDIDDocument) {
		return fmt.Errorf("update DID document: %w", resolver.ErrDeactivated)
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, didnuts.NutsDIDContextV1URI())
	next = withJSONLDContext(next, didnuts.JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	if err = didnuts.ManagedDocumentValidator(r.serviceResolver).Validate(next); err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	controller, key, err := r.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// for the metadata
	_, controllerMeta, err := r.didResolver.Resolve(controller.ID, nil)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(didnuts.DIDDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = r.network.CreateTransaction(ctx, tx)
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

func (r *Module) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, crypto.Key, error) {
	controllers, err := didnuts.ResolveControllers(r.store, doc, nil)
	if err != nil {
		return did.Document{}, nil, fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, nil, fmt.Errorf("could not find any controllers for document")
	}

	var key crypto.Key
	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			key, err = r.keyStore.Resolve(ctx, cik.ID.String())
			if err == nil {
				return c, key, nil
			}
		}
	}

	if errors.Is(err, crypto.ErrPrivateKeyNotFound) {
		return did.Document{}, nil, resolver.ErrDIDNotManagedByThisNode
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
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
