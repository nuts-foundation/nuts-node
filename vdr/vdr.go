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
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ types.VDR = (*VDR)(nil)

// didStoreName contains the name for the store
const didStoreName = "didstore"

// VDR stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type VDR struct {
	config            Config
	store             didstore.Store
	network           network.Transactions
	networkAmbassador Ambassador
	didDocCreator     types.DocCreator
	didResolver       *didservice.DIDResolverRouter
	// did:nuts is also handled by the router, but it has some special functions for resolving controllers
	// which VDR uses, so we need a reference here to use it.
	// We could abstract DID document updating (so other DID methods can be updated through the same API),
	// which would make this reference go away.
	nutsDidResolver *didservice.NutsDIDResolver
	serviceResolver types.ServiceResolver
	documentOwner   types.DocumentOwner
	keyStore        crypto.KeyStore
	storageProvider storage.Provider
	eventManager    events.Event
}

func (r *VDR) Resolver() types.DIDResolver {
	return r.didResolver
}

// NewVDR creates a new VDR with provided params
func NewVDR(config Config, storageProvider storage.Provider, cryptoClient crypto.KeyStore, networkClient network.Transactions,
	didResolverRouter *didservice.DIDResolverRouter, eventManager events.Event) *VDR {
	return &VDR{
		config:          config,
		storageProvider: storageProvider,
		network:         networkClient,
		eventManager:    eventManager,
		didDocCreator:   didservice.Creator{KeyStore: cryptoClient},
		didResolver:     didResolverRouter,
		serviceResolver: didservice.ServiceResolver{Resolver: didResolverRouter},
		documentOwner:   newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: cryptoClient}, didResolverRouter),
		keyStore:        cryptoClient,
	}
}

func (r *VDR) Name() string {
	return ModuleName
}

func (r *VDR) Config() interface{} {
	return &r.config
}

// Configure configures the VDR engine.
func (r *VDR) Configure(_ core.ServerConfig) error {
	didStore, err := r.storageProvider.GetKVStore(didStoreName, storage.PersistentStorageClass)
	if err != nil {
		return err
	}
	r.store = didstore.New(didStore)

	r.nutsDidResolver = &didservice.NutsDIDResolver{Store: r.store}
	r.networkAmbassador = NewAmbassador(r.network, r.store, r.eventManager)

	for _, method := range r.config.Methods {
		switch method {
		case "nuts":
			r.didResolver.Register(method, r.nutsDidResolver)
		case "web":
			r.didResolver.Register(method, didservice.NewWebResolver())
		default:
			return fmt.Errorf("unsupported DID method: %s", method)
		}
	}
	// Initiate the routines for auto-updating the data.
	r.networkAmbassador.Configure()
	return nil
}

func (r *VDR) Start() error {
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

	err = r.network.DiscoverNodes(didservice.Finder{Store: r.store})
	if err != nil {
		return fmt.Errorf("network node discovery failed: %w", err)
	}

	return err
}

func (r *VDR) Shutdown() error {
	return nil
}

func (r *VDR) ConflictedDocuments() ([]did.Document, []types.DocumentMetadata, error) {
	conflictedDocs := make([]did.Document, 0)
	conflictedMeta := make([]types.DocumentMetadata, 0)

	err := r.store.Conflicted(func(doc did.Document, metadata types.DocumentMetadata) error {
		conflictedDocs = append(conflictedDocs, doc)
		conflictedMeta = append(conflictedMeta, metadata)
		return nil
	})
	return conflictedDocs, conflictedMeta, err
}

func (r *VDR) IsOwner(ctx context.Context, id did.DID) (bool, error) {
	return r.documentOwner.IsOwner(ctx, id)
}

func (r *VDR) ListOwned(ctx context.Context) ([]did.DID, error) {
	return r.documentOwner.ListOwned(ctx)
}

// newOwnConflictedDocIterator accepts two counters and returns a new DocIterator that counts the total number of
// conflicted documents, both total and owned by this node.
func (r *VDR) newOwnConflictedDocIterator(totalCount, ownedCount *int) types.DocIterator {
	return func(doc did.Document, metadata types.DocumentMetadata) error {
		*totalCount++
		controllers, err := didservice.ResolveControllers(r.nutsDidResolver, doc, nil)
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
func (r *VDR) Diagnostics() []core.DiagnosticResult {
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
func (r *VDR) Create(ctx context.Context, options types.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	log.Logger().Debug("Creating new DID Document.")

	// for all controllers given in the options, we need to capture the metadata so the new transaction can reference to it
	// holder for all metadata of the controllers
	controllerMetadata := make([]types.DocumentMetadata, len(options.Controllers))

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

	doc, key, err := r.didDocCreator.Create(ctx, options)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create DID document: %w", err)
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}

	// extract the transaction refs from the controller metadata
	refs := make([]hash.SHA256Hash, 0)
	for _, meta := range controllerMetadata {
		refs = append(refs, meta.SourceTransactions...)
	}

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
	_, err = r.network.CreateTransaction(ctx, tx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not store DID document in network: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldDID, doc.ID).
		Info("New DID Document created")

	return doc, key, nil
}

// Update updates a DID Document based on the DID
func (r *VDR) Update(ctx context.Context, id did.DID, next did.Document) error {
	log.Logger().
		WithField(core.LogFieldDID, id).
		Debug("Updating DID Document")
	resolverMetadata := &types.ResolveMetadata{
		AllowDeactivated: true,
	}

	// Since the update mechanism is "did:nuts"-specific, we can't accidentally update a non-"did:nuts" document,
	// but check it defensively to avoid obscure errors later.
	if id.Method != didservice.NutsDIDMethodName {
		return fmt.Errorf("can't update DID document of type: %s", id.Method)
	}

	currentDIDDocument, currentMeta, err := r.store.Resolve(id, resolverMetadata)
	if err != nil {
		return fmt.Errorf("update DID document: %w", err)
	}
	if didservice.IsDeactivated(*currentDIDDocument) {
		return fmt.Errorf("update DID document: %w", types.ErrDeactivated)
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, didservice.NutsDIDContextV1URI())
	next = withJSONLDContext(next, didservice.JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	if err = ManagedDocumentValidator(r.serviceResolver).Validate(next); err != nil {
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

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = r.network.CreateTransaction(ctx, tx)
	if err != nil {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrPrivateKeyNotFound) {
			err = types.ErrDIDNotManagedByThisNode
		}
		return fmt.Errorf("update DID document: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldDID, id).
		Info("DID Document updated")

	return nil
}

func (r *VDR) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, crypto.Key, error) {
	controllers, err := didservice.ResolveControllers(r.nutsDidResolver, doc, nil)
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
		return did.Document{}, nil, types.ErrDIDNotManagedByThisNode
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}

func withJSONLDContext(document did.Document, ctx ssi.URI) did.Document {
	contextPresent := false

	for _, c := range document.Context {
		if c.String() == ctx.String() {
			contextPresent = true
		}
	}

	if !contextPresent {
		document.Context = append(document.Context, ctx)
	}
	return document
}
