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
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didjwk"
	"github.com/nuts-foundation/nuts-node/vdr/didkey"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	didnutsStore "github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// ModuleName is the name of the engine
const ModuleName = "VDR"

var _ VDR = (*Module)(nil)
var _ core.Named = (*Module)(nil)
var _ core.Configurable = (*Module)(nil)
var _ didsubject.SubjectManager = (*Module)(nil)

// Module implements VDR, which stands for the Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type Module struct {
	config            Config
	publicURL         *url.URL
	store             didnutsStore.Store
	network           network.Transactions
	networkAmbassador didnuts.Ambassador
	documentOwner     didsubject.DocumentOwner
	// nutsDocumentManager is used to manage did:nuts DID Documents
	// Deprecated: used by v1 api
	nutsDocumentManager didsubject.DocumentManager
	// didResolver is used to resolve all/other DID Documents
	didResolver resolver.DIDResolver
	// ownedDIDResolver is used to resolve DID Documents managed by this node
	ownedDIDResolver resolver.DIDResolver
	keyStore         crypto.KeyStore
	storageInstance  storage.Engine
	eventManager     events.Event

	// new style DID management
	didsubject.Manager

	// Start/Shutdown
	ctx      context.Context
	cancel   context.CancelFunc
	routines *sync.WaitGroup
}

func (r *Module) PublicURL() *url.URL {
	return r.publicURL
}

// ResolveManaged resolves a DID document that is managed by the local node.
func (r *Module) ResolveManaged(id did.DID) (*did.Document, error) {
	document, _, err := r.ownedDIDResolver.Resolve(id, nil)
	return document, err
}

// Resolve resolves any DID document which DID method is supported.
// To only resolve DID documents managed by the local node, use ResolveManaged().
func (r *Module) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	return r.didResolver.Resolve(id, metadata)
}

func (r *Module) Resolver() resolver.DIDResolver {
	return r.didResolver
}

func (r *Module) SupportedMethods() []string {
	return r.config.DIDMethods
}

// NewVDR creates a new Module with provided params
func NewVDR(cryptoClient crypto.KeyStore, networkClient network.Transactions,
	didStore didnutsStore.Store, eventManager events.Event, storageInstance storage.Engine) *Module {
	m := &Module{
		didResolver:     &resolver.DIDResolverRouter{},
		network:         networkClient,
		eventManager:    eventManager,
		store:           didStore,
		keyStore:        cryptoClient,
		storageInstance: storageInstance,
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.routines = new(sync.WaitGroup)
	return m
}

func (r *Module) Name() string {
	return ModuleName
}

func (r *Module) Config() interface{} {
	return &r.config
}

// Configure configures the Module engine.
func (r *Module) Configure(config core.ServerConfig) error {
	var err error
	if r.publicURL, err = config.ServerURL(); err != nil {
		return err
	}
	// at least one method should be configured
	if len(r.config.DIDMethods) == 0 {
		return errors.New("at least one DID method should be configured")
	}
	// check if all configured methods are supported
	for _, method := range r.config.DIDMethods {
		switch method {
		case didnuts.MethodName, didweb.MethodName:
			continue
		default:
			return fmt.Errorf("unsupported DID method: %s", method)
		}
	}

	r.networkAmbassador = didnuts.NewAmbassador(r.network, r.store, r.eventManager)
	db := r.storageInstance.GetSQLDatabase()
	methodManagers := map[string]didsubject.MethodManager{}

	r.didResolver.(*resolver.DIDResolverRouter).Register(didjwk.MethodName, didjwk.NewResolver())
	r.didResolver.(*resolver.DIDResolverRouter).Register(didkey.MethodName, didkey.NewResolver())
	// Register DID resolver and DID methods we can resolve
	r.ownedDIDResolver = didsubject.Resolver{DB: db}

	// Methods we can produce from the Nuts node
	// did:nuts
	nutsManager := didnuts.NewManager(r.keyStore, r.network, r.store, r.didResolver, db)
	r.nutsDocumentManager = nutsManager
	methodManagers = map[string]didsubject.MethodManager{}
	r.documentOwner = &MultiDocumentOwner{
		DocumentOwners: []didsubject.DocumentOwner{
			newCachingDocumentOwner(DBDocumentOwner{DB: db}, r.didResolver),
			newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: r.keyStore}, r.didResolver),
		},
	}
	if slices.Contains(r.config.DIDMethods, didnuts.MethodName) {
		methodManagers[didnuts.MethodName] = nutsManager
		r.didResolver.(*resolver.DIDResolverRouter).Register(didnuts.MethodName, &didnuts.Resolver{Store: r.store})
	}

	// did:web
	publicURL, err := config.ServerURL()
	if err != nil {
		return err
	}
	rootDID, err := didweb.URLToDID(*publicURL)
	if err != nil {
		return err
	}
	webManager := didweb.NewManager(*rootDID, "iam", r.keyStore, db)
	webResolver := resolver.ChainedDIDResolver{
		Resolvers: []resolver.DIDResolver{
			// did:web resolver should first look in own database, then resolve over the web
			r.ownedDIDResolver,
			didweb.NewResolver(),
		},
	}
	if slices.Contains(r.config.DIDMethods, didweb.MethodName) {
		methodManagers[didweb.MethodName] = webManager
		r.didResolver.(*resolver.DIDResolverRouter).Register(didweb.MethodName, webResolver)
	}

	r.Manager = didsubject.Manager{DB: db, MethodManagers: methodManagers, PreferredOrder: r.config.DIDMethods}

	// Initiate the routines for auto-updating the data.
	return r.networkAmbassador.Configure()
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

	// start DID Document rollback loop
	r.routines.Add(1)
	go func() {
		defer r.routines.Done()
		r.rollbackLoop()
	}()

	return err
}

// rollbackLoop checks every minute if there are any DID documents that need to be rolled back.
// uses rollback() to do the actual work.
func (r *Module) rollbackLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// run once at startup
	r.Rollback(r.ctx)
	for {
		select {
		// stop at shutdown
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			// run every minute
			r.Rollback(r.ctx)
		}
	}
}

func (r *Module) Shutdown() error {
	r.cancel()
	r.routines.Wait()
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

// NutsDocumentManager returns the nuts document manager
// Deprecated
func (r *Module) NutsDocumentManager() didsubject.DocumentManager {
	return r.nutsDocumentManager
}

func (r *Module) DocumentOwner() didsubject.DocumentOwner {
	return r.documentOwner
}

// newOwnConflictedDocIterator accepts two counters and returns a new DocIterator that counts the total number of
// conflicted documents, both total and owned by this node.
func (r *Module) newOwnConflictedDocIterator(totalCount, ownedCount *int) resolver.DocIterator {
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
			isOwned, err := r.DocumentOwner().IsOwner(context.TODO(), controller.ID)
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

func (r *Module) Migrate() error {
	// Find all documents that are managed by this node
	owned, err := r.DocumentOwner().ListOwned(context.Background())
	if err != nil {
		return err
	}
	auditContext := audit.Context(context.Background(), "system", ModuleName, "migrate")
	// resolve the DID Document if the did starts with did:nuts
	for _, did := range owned {
		if did.Method == didnuts.MethodName {
			doc, _, err := r.Resolve(did, nil)
			if err != nil {
				if !(errors.Is(err, resolver.ErrDeactivated) || errors.Is(err, resolver.ErrNoActiveController)) {
					log.Logger().WithError(err).WithField(core.LogFieldDID, did.String()).Error("Could not update owned DID document, continuing with next document")
				}
				continue
			}
			if len(doc.Controller) > 0 {
				doc.Controller = nil

				if len(doc.VerificationMethod) == 0 {
					log.Logger().WithField(core.LogFieldDID, doc.ID.String()).Warnf("No verification method found in owned DID document")
					continue
				}

				if len(doc.CapabilityInvocation) == 0 {
					// add all keys as capabilityInvocation keys
					for _, vm := range doc.VerificationMethod {
						doc.CapabilityInvocation.Add(vm)
					}
				}

				err = r.nutsDocumentManager.Update(auditContext, did, *doc)
				if err != nil {
					if !(errors.Is(err, resolver.ErrKeyNotFound)) {
						log.Logger().WithError(err).WithField(core.LogFieldDID, did.String()).Error("Could not update owned DID document, continuing with next document")
					}
				}
			}
		}
	}
	return nil
}
