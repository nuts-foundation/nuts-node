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
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// VDR stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type VDR struct {
	config            Config
	store             didstore.Store
	network           network.Transactions
	OnChange          func(registry *VDR)
	networkAmbassador Ambassador
	didDocCreator     types.DocCreator
	didDocResolver    types.DocResolver
	keyStore          crypto.KeyStore
}

// NewVDR creates a new VDR with provided params
func NewVDR(config Config, cryptoClient crypto.KeyStore, networkClient network.Transactions, store didstore.Store, eventManager events.Event) *VDR {
	return &VDR{
		config:            config,
		network:           networkClient,
		store:             store,
		didDocCreator:     didservice.Creator{KeyStore: cryptoClient},
		didDocResolver:    didservice.Resolver{Store: store},
		networkAmbassador: NewAmbassador(networkClient, store, eventManager),
		keyStore:          cryptoClient,
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

// newOwnConflictedDocIterator accepts two counters and returns a new DocIterator that counts the total number of
// conflicted documents, both total and owned by this node.
func (r *VDR) newOwnConflictedDocIterator(totalCount, ownedCount *int) types.DocIterator {
	return func(doc did.Document, metadata types.DocumentMetadata) error {
		*totalCount++
		controllers, err := r.didDocResolver.ResolveControllers(doc, nil)
		if err != nil {
			log.Logger().
				WithField(core.LogFieldDID, doc.ID).
				WithError(err).
				Info("failed to resolve controller of conflicted DID document")
			return nil
		}
		for _, controller := range controllers {
			for _, vr := range controller.CapabilityInvocation {
				// TODO: Fix context.TODO() when we have a context in the Diagnostics() method
				if r.keyStore.Exists(context.TODO(), vr.ID.String()) {
					*ownedCount++
					return nil
				}
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
	doc, key, err := r.didDocCreator.Create(ctx, options)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create DID document: %w", err)
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAttachKey()
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

	currentDIDDocument, currentMeta, err := r.store.Resolve(id, resolverMetadata)
	if err != nil {
		return err
	}
	if didservice.IsDeactivated(*currentDIDDocument) {
		return types.ErrDeactivated
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, didservice.NutsDIDContextV1URI())
	next = withJSONLDContext(next, didservice.JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	if err = ManagedDocumentValidator(didservice.NewServiceResolver(r.didDocResolver)).Validate(next); err != nil {
		return err
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	controller, key, err := r.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		return err
	}

	// for the metadata
	_, controllerMeta, err := r.didDocResolver.Resolve(controller.ID, nil)
	if err != nil {
		return err
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = r.network.CreateTransaction(ctx, tx)
	if err == nil {
		log.Logger().
			WithField(core.LogFieldDID, id).
			Info("DID Document updated")
	} else {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrPrivateKeyNotFound) {
			return types.ErrDIDNotManagedByThisNode
		}
	}

	return err
}

func (r *VDR) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, crypto.Key, error) {
	controllers, err := r.didDocResolver.ResolveControllers(doc, nil)
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
