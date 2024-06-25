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
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/audit"
	events2 "github.com/nuts-foundation/nuts-node/vdr/events"
	"github.com/nuts-foundation/nuts-node/vdr/sql"
	"gorm.io/gorm"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
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
var _ management.SubjectManager = (*Module)(nil)

// Module implements VDR, which stands for the Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type Module struct {
	store               didnutsStore.Store
	network             network.Transactions
	networkAmbassador   didnuts.Ambassador
	documentOwner       management.DocumentOwner
	nutsDocumentManager management.DocumentManager
	didResolver         resolver.DIDResolver
	sqlDIDResolver      resolver.DIDResolver
	serviceResolver     resolver.ServiceResolver
	keyStore            crypto.KeyStore
	storageInstance     storage.Engine
	eventManager        events.Event

	// new style DID management
	db            *gorm.DB
	eventManagers map[string]events2.MethodManager
}

// ResolveManaged resolves a DID document that is managed by the local node.
func (r *Module) ResolveManaged(id did.DID) (*did.Document, error) {
	document, _, err := r.sqlDIDResolver.Resolve(id, nil)
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
	r.db = r.storageInstance.GetSQLDatabase()
	r.sqlDIDResolver = sql.Resolver{DB: r.db}

	// Methods we can produce from the Nuts node
	// did:nuts
	nutsManager := didnuts.NewManager(r.keyStore, r.network, r.store, r.didResolver, r.db)
	r.nutsDocumentManager = nutsManager
	r.documentOwner = &MultiDocumentOwner{
		DocumentOwners: []management.DocumentOwner{
			newCachingDocumentOwner(DBDocumentOwner{DB: r.db}, r.didResolver),
			newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: r.keyStore}, r.didResolver),
		},
	}
	//r.documentOwner = newCachingDocumentOwner(DBDocumentOwner{DB: r.db}, r.didResolver)
	//r.documentOwner = newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: r.keyStore}, r.didResolver)

	// did:web
	publicURL, err := config.ServerURL()
	if err != nil {
		return err
	}
	rootDID, err := didweb.URLToDID(*publicURL)
	if err != nil {
		return err
	}
	webManager := didweb.NewManager(*rootDID, "iam", r.keyStore, r.db)
	// did:web resolver should first look in own database, then resolve over the web
	webResolver := resolver.ChainedDIDResolver{
		Resolvers: []resolver.DIDResolver{
			r.sqlDIDResolver,
			didweb.NewResolver(),
		},
	}

	// eventing
	r.eventManagers = map[string]events2.MethodManager{
		didnuts.MethodName: nutsManager,
		didweb.MethodName:  webManager,
	}

	// Register DID methods we can resolve
	r.didResolver.(*resolver.DIDResolverRouter).Register(didnuts.MethodName, &didnuts.Resolver{Store: r.store})
	r.didResolver.(*resolver.DIDResolverRouter).Register(didweb.MethodName, webResolver)
	r.didResolver.(*resolver.DIDResolverRouter).Register(didjwk.MethodName, didjwk.NewResolver())
	r.didResolver.(*resolver.DIDResolverRouter).Register(didkey.MethodName, didkey.NewResolver())

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

	// start loops for event managers
	// todo

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

func (r *Module) NutsDocumentManager() management.DocumentManager {
	return r.nutsDocumentManager
}

func (r *Module) DocumentOwner() management.DocumentOwner {
	return r.documentOwner
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
				return fmt.Errorf("could not resolve owned DID document: %w", err)
			}
			if len(doc.Controller) > 0 {
				doc.Controller = nil

				if len(doc.VerificationMethod) == 0 {
					log.Logger().Warnf("No verification method found in owned DID document (did=%s)", did.String())
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
					return fmt.Errorf("could not update owned DID document: %w", err)
				}
			}
		}
	}
	return nil
}

// Create generates a new DID Document
func (r *Module) Create(ctx context.Context, options management.CreationOptions) ([]did.Document, string, error) {
	log.Logger().Debug("Creating new DID Documents.")

	// todo keyTypes
	keyFlags := management.CapabilityInvocationUsage | management.AssertionMethodUsage | management.AuthenticationUsage | management.CapabilityDelegationUsage

	// todo
	subject := uuid.New().String()

	// call generate on all managers
	docs := make(map[string]did.Document)
	for method, manager := range r.eventManagers {
		doc, err := manager.GenerateDocument(ctx, subject, keyFlags)
		if err != nil {
			return nil, "", fmt.Errorf("could not generate DID document (method %s): %w", method, err)
		}
		docs[method] = *doc
	}

	// then store all docs in the sql db with matching events
	sqlDocs := make([]sql.DIDDocument, 0)
	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		for method, doc := range docs {
			// Create sql.DID
			sqlDID := sql.DID{
				ID:      doc.ID.String(),
				Subject: subject,
			}

			// Create verificationMethods
			keyTypes := sql.VerificationMethodKeyType(management.CapabilityInvocationUsage | management.AssertionMethodUsage)
			data, _ := json.Marshal(doc.VerificationMethod[0]) //todo
			vms := []sql.VerificationMethod{
				{
					ID:       doc.VerificationMethod[0].ID.String(),
					KeyTypes: keyTypes, // todo
					Data:     data,
				},
			}

			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, vms, nil)
			if err != nil {
				return events, err
			}
			// create and store event todo
			sqlDocs = append(sqlDocs, *sqlDoc)
			events[method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDoc.ID,
				EventType:            events2.DIDEventCreated, // todo could also be update
				DIDDocumentVersion:   *sqlDoc,
			}
		}
		return events, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("could not store DID documents: %w", err)
	}

	allDocs := make([]did.Document, 0)
	for _, doc := range docs {
		allDocs = append(allDocs, doc)
	}
	return allDocs, subject, nil
}

func (r *Module) Deactivate(ctx context.Context, subject string) error {
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Debug("Deactivating DID Documents")

	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDManager := sql.NewDIDManager(tx)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return events, err
		}
		if len(dids) == 0 {
			return nil, resolver.ErrNotFound
		}
		for _, sqlDID := range dids {
			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, nil, nil)
			if err != nil {
				return events, err
			}
			id, _ := did.ParseDID(sqlDID.ID)
			events[id.Method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDID.ID,
				EventType:            events2.DIDEventDeactivated,
				DIDDocumentVersion:   *sqlDoc,
			}
		}
		return events, nil
	})
	if err != nil {
		return fmt.Errorf("could not deactivate DID documents: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Info("DID Documents deactivated")
	return nil
}

// CreateService creates a new service in the DID document identified by subjectDID.
func (r *Module) CreateService(ctx context.Context, subject string, service did.Service) ([]did.Service, error) {
	services := make([]did.Service, 0)

	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDManager := sql.NewDIDManager(tx)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return events, err
		}
		for _, sqlDID := range dids {
			// find current document
			id, _ := did.ParseDID(sqlDID.ID)
			current, err := sqlDIDDocumentManager.Latest(*id)
			if err != nil {
				return events, err
			}
			// construct new service
			// todo generate ID using hashing
			if service.ID.String() == "" {
				// Generate random service ID
				serviceID := did.DIDURL{
					DID:      *id,
					Fragment: uuid.NewString(),
				}
				service.ID = serviceID.URI()
			}
			asJson, err := json.Marshal(service)
			if err != nil {
				return events, err
			}
			sqlService := sql.SqlService{
				ID:            service.ID.String(),
				DIDDocumentID: current.DidID,
				Data:          asJson,
			}

			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, current.VerificationMethods, append(current.Services, sqlService))
			if err != nil {
				return events, err
			}
			events[id.Method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDID.ID,
				EventType:            events2.DIDEventUpdated,
				DIDDocumentVersion:   *sqlDoc,
			}
			services = append(services, service)
		}
		return events, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not add service to DID Documents: %w", err)
	}

	return services, nil
}

func (r *Module) FindServices(_ context.Context, subject string, serviceType *string) ([]did.Service, error) {
	sqlDIDManager := sql.NewDIDManager(r.db)
	dids, err := sqlDIDManager.FindBySubject(subject)
	if err != nil {
		return nil, err
	}
	services := make([]did.Service, 0)
	// for detecting duplicates
	serviceMap := make(map[string]struct{})
	for _, sqlDID := range dids {
		id, _ := did.ParseDID(sqlDID.ID)
		current, err := sql.NewDIDDocumentManager(r.db).Latest(*id)
		if err != nil {
			return nil, err
		}
		for _, service := range current.Services {
			if _, ok := serviceMap[service.ID]; ok {
				continue
			}
			serviceMap[service.ID] = struct{}{}
			var s did.Service
			err := json.Unmarshal(service.Data, &s)
			if err != nil {
				return nil, err
			}
			if serviceType != nil && s.Type == *serviceType {
				services = append(services, s)
			}
		}
	}
	return services, nil
}

// DeleteService removes a service from the DID document identified by subjectDID.
func (r *Module) DeleteService(ctx context.Context, subject string, serviceID ssi.URI) error {
	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDManager := sql.NewDIDManager(tx)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		fragmentID := "#" + serviceID.Fragment
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return events, err
		}
		for _, sqlDID := range dids {
			id, _ := did.ParseDID(sqlDID.ID)
			current, err := sqlDIDDocumentManager.Latest(*id)
			if err != nil {
				return events, err
			}

			services := current.Services
			j := 0
			for i, s := range services {
				if s.ID == fragmentID {
					continue
				}
				services[j] = services[i]
				j++
			}
			services = services[:j]
			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(current.DID, current.VerificationMethods, services)
			if err != nil {
				return events, err
			}
			events[id.Method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDID.ID,
				EventType:            events2.DIDEventUpdated,
				DIDDocumentVersion:   *sqlDoc,
			}
		}

		return events, err
	})

	if err != nil {
		return fmt.Errorf("could not delete service from DID Documents: %w", err)
	}
	return nil
}

func (r *Module) UpdateService(ctx context.Context, subject string, serviceID ssi.URI, service did.Service) ([]did.Service, error) {
	newServices := make([]did.Service, 0)

	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDManager := sql.NewDIDManager(tx)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		fragmentID := "#" + serviceID.Fragment
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return events, err
		}
		for _, sqlDID := range dids {
			id, _ := did.ParseDID(sqlDID.ID)
			current, err := sqlDIDDocumentManager.Latest(*id)
			if err != nil {
				return events, err
			}

			// remove old
			services := current.Services
			j := 0
			for i, s := range services {
				if s.ID == fragmentID {
					continue
				}
				services[j] = services[i]
				j++
			}
			services = services[:j]

			// add new
			// todo generate ID using hashing
			if service.ID.String() == "" {
				// Generate random service ID
				serviceID := did.DIDURL{
					DID:      *id,
					Fragment: uuid.NewString(),
				}
				service.ID = serviceID.URI()
			}
			asJson, err := json.Marshal(service)
			if err != nil {
				return events, err
			}
			sqlService := sql.SqlService{
				ID:            service.ID.String(),
				DIDDocumentID: current.DidID,
				Data:          asJson,
			}
			services = append(services, sqlService)
			newServices = append(newServices, service)

			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(current.DID, current.VerificationMethods, services)
			if err != nil {
				return events, err
			}
			events[id.Method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDID.ID,
				EventType:            events2.DIDEventUpdated,
				DIDDocumentVersion:   *sqlDoc,
			}
		}

		return events, err
	})
	if err != nil {
		return nil, fmt.Errorf("could not update service for DID Documents: %w", err)
	}
	return newServices, nil
}

func (r *Module) AddVerificationMethod(ctx context.Context, subject string, keyUsage management.DIDKeyFlags) ([]did.VerificationMethod, error) {
	log.Logger().Debug("Creating new VerificationMethods.")

	// todo keyTypes
	keyTypes := sql.VerificationMethodKeyType(management.CapabilityInvocationUsage | management.AssertionMethodUsage)

	// call generate on all managers
	vms := make(map[string]did.VerificationMethod)

	err := r.transactionEventHelper(ctx, func(tx *gorm.DB) (map[string]sql.DIDEventLog, error) {
		events := make(map[string]sql.DIDEventLog)
		sqlDIDManager := sql.NewDIDManager(tx)
		sqlDIDDocumentManager := sql.NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return events, err
		}
		for _, sqlDID := range dids {
			id, _ := did.ParseDID(sqlDID.ID)
			latest, err := sqlDIDDocumentManager.Latest(*id)
			if err != nil {
				return events, err
			}
			vm, err := r.eventManagers[id.Method].GenerateVerificationMethod(ctx, *id)
			if err != nil {
				return events, err
			}
			vms[id.Method] = *vm
			data, _ := json.Marshal(*vm)
			sqlMethod := sql.VerificationMethod{
				ID:       vm.ID.String(),
				KeyTypes: keyTypes,
				Data:     data,
			}
			latest.VerificationMethods = append(latest.VerificationMethods, sqlMethod)
			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, latest.VerificationMethods, latest.Services)
			if err != nil {
				return events, err
			}
			// create and store event
			events[id.Method] = sql.DIDEventLog{
				DIDDocumentVersionID: sqlDoc.ID,
				EventType:            events2.DIDEventUpdated,
				DIDDocumentVersion:   *sqlDoc,
			}
		}
		return events, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not update DID documents: %w", err)
	}
	allMethods := make([]did.VerificationMethod, 0)
	for _, vm := range vms {
		allMethods = append(allMethods, vm)
	}
	return allMethods, nil
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

// TransactionEventHelper is a helper function that starts a transaction, performs an operation, and emits an event.
func (r *Module) transactionEventHelper(ctx context.Context, operation func(tx *gorm.DB) (map[string]sql.DIDEventLog, error)) error {
	var events map[string]sql.DIDEventLog
	var err error
	err = r.db.Transaction(func(tx *gorm.DB) error {
		// Perform the operation within the transaction.
		events, err = operation(tx)
		if err != nil {
			return err
		}

		// Save all events
		for _, e := range events {
			err = tx.Save(&e).Error
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Call OnEvent for all managers on the created docs
	for method, manager := range r.eventManagers {
		manager.OnEvent(ctx, events[method])
	}

	return nil
}
