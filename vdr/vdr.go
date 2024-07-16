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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"sync"
	"time"

	ssi "github.com/nuts-foundation/go-did"
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
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
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
	store               didnutsStore.Store
	network             network.Transactions
	networkAmbassador   didnuts.Ambassador
	documentOwner       didsubject.DocumentOwner
	nutsDocumentManager didsubject.DocumentManager
	didResolver         resolver.DIDResolver
	sqlDIDResolver      resolver.DIDResolver
	serviceResolver     resolver.ServiceResolver
	keyStore            crypto.KeyStore
	storageInstance     storage.Engine
	eventManager        events.Event

	// new style DID management
	db             *gorm.DB
	methodManagers map[string]didsubject.MethodManager

	// Start/Shutdown
	ctx      context.Context
	cancel   context.CancelFunc
	routines *sync.WaitGroup
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
	m := &Module{
		network:         networkClient,
		eventManager:    eventManager,
		didResolver:     didResolver,
		store:           didStore,
		serviceResolver: resolver.DIDServiceResolver{Resolver: didResolver},
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

// Configure configures the Module engine.
func (r *Module) Configure(config core.ServerConfig) error {
	r.networkAmbassador = didnuts.NewAmbassador(r.network, r.store, r.eventManager)
	r.db = r.storageInstance.GetSQLDatabase()
	r.sqlDIDResolver = didsubject.Resolver{DB: r.db}

	// Methods we can produce from the Nuts node
	// did:nuts
	nutsManager := didnuts.NewManager(r.keyStore, r.network, r.store, r.didResolver, r.db)
	r.nutsDocumentManager = nutsManager
	r.documentOwner = &MultiDocumentOwner{
		DocumentOwners: []didsubject.DocumentOwner{
			newCachingDocumentOwner(DBDocumentOwner{DB: r.db}, r.didResolver),
			newCachingDocumentOwner(privateKeyDocumentOwner{keyResolver: r.keyStore}, r.didResolver),
		},
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
	webManager := didweb.NewManager(*rootDID, "iam", r.keyStore, r.db)
	// did:web resolver should first look in own database, then resolve over the web
	webResolver := resolver.ChainedDIDResolver{
		Resolvers: []resolver.DIDResolver{
			r.sqlDIDResolver,
			didweb.NewResolver(),
		},
	}

	// methods
	r.methodManagers = map[string]didsubject.MethodManager{
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

	// start DID Document rollback loop
	r.routines.Add(1)
	go func() {
		defer r.routines.Done()
		r.rollbackLoop()
	}()

	return err
}

func (r *Module) rollbackLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// run once at startup
	r.rollback(r.ctx)
	for {
		select {
		// stop at shutdown
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			// run every minute
			r.rollback(r.ctx)
		}
	}
}

func (r *Module) rollback(ctx context.Context) {
	updatedAt := time.Now().Add(-time.Minute).Unix()
	err := r.db.Transaction(func(tx *gorm.DB) error {
		changes := make([]didsubject.DIDChangeLog, 0)
		groupedChanges := make(map[string][]didsubject.DIDChangeLog)
		// find all DIDChangeLog inner join with DIDDocumentVersion where document.updated_at < now - 1 minute
		err := tx.Preload("DIDDocumentVersion").Preload("DIDDocumentVersion.DID").InnerJoins("DIDDocumentVersion", tx.Where("DIDDocumentVersion.updated_at < ?", updatedAt)).Find(&changes).Error
		if err != nil {
			return err
		}
		// group on transaction_id
		for _, change := range changes {
			groupedChanges[change.TransactionID] = append(groupedChanges[change.TransactionID], change)
		}
		// check per transaction_id if all are committed
		for transactionID, versionChanges := range groupedChanges {
			committed := true
			for _, change := range versionChanges {
				committed, err = r.methodManagers[change.Method()].IsCommitted(ctx, change)
				if err != nil {
					return err
				}
				if !committed {
					break
				}
			}
			// if one failed, delete all document versions for this transaction_id
			if !committed {
				for _, change := range versionChanges {
					err := tx.Where("id = ?", change.DIDDocumentVersionID).Delete(&didsubject.DIDDocument{}).Error
					if err != nil {
						return err
					}
				}
			}
			// delete all changes, also done via cascading in case of !committed, but less code this way
			err = tx.Where("transaction_id = ?", transactionID).Delete(&didsubject.DIDChangeLog{}).Error
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Logger().WithError(err).Error("failed to rollback DID documents")
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

func (r *Module) NutsDocumentManager() didsubject.DocumentManager {
	return r.nutsDocumentManager
}

func (r *Module) DocumentOwner() didsubject.DocumentOwner {
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

func (r *Module) List(_ context.Context, subject string) ([]did.DID, error) {
	sqlDIDManager := didsubject.NewDIDManager(r.db)
	dids, err := sqlDIDManager.FindBySubject(subject)
	if err != nil {
		return nil, err
	}
	result := make([]did.DID, len(dids))
	for i, sqlDID := range dids {
		id, err := did.ParseDID(sqlDID.ID)
		if err != nil {
			return nil, err
		}
		result[i] = *id
	}
	return result, nil
}

// Create generates new DID Documents
func (r *Module) Create(ctx context.Context, options didsubject.CreationOptions) ([]did.Document, string, error) {
	log.Logger().Debug("Creating new DID Documents.")

	// defaults
	keyFlags := didsubject.AssertionKeyUsage()
	subject := uuid.New().String()

	// apply options
	for _, option := range options.All() {
		switch opt := option.(type) {
		case didsubject.SubjectCreationOption:
			subject = opt.Subject
		case didsubject.EncryptionKeyCreationOption:
			keyFlags = keyFlags | didsubject.EncryptionKeyUsage()
		default:
			return nil, "", fmt.Errorf("unknown option: %T", option)
		}
	}

	sqlDocs := make(map[string]didsubject.DIDDocument)
	err := r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]didsubject.DIDChangeLog, error) {
		// check existence
		sqlDIDManager := didsubject.NewDIDManager(tx)
		exists, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return nil, err
		}
		if len(exists) > 0 {
			return nil, didsubject.ErrDIDAlreadyExists
		}

		// call generate on all managers
		for method, manager := range r.methodManagers {
			sqlDoc, err := manager.NewDocument(ctx, keyFlags)
			if err != nil {
				return nil, fmt.Errorf("could not generate DID document (method %s): %w", method, err)
			}
			sqlDocs[method] = *sqlDoc
		}

		alsoKnownAs := make([]didsubject.DID, 0)
		for _, sqlDoc := range sqlDocs {
			alsoKnownAs = append(alsoKnownAs, sqlDoc.DID)
		}

		// then store all docs in the sql db with matching events
		changes := make(map[string]didsubject.DIDChangeLog)
		sqlDIDDocumentManager := didsubject.NewDIDDocumentManager(tx)
		transactionId := uuid.New().String()
		for method, sqlDoc := range sqlDocs {
			// overwrite sql.DID from returned document because we have the subject and alsoKnownAs here
			sqlDID := didsubject.DID{
				ID:      sqlDoc.DID.ID,
				Subject: subject,
				Aka:     alsoKnownAs,
			}
			createdDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, sqlDoc.VerificationMethods, nil)
			if err != nil {
				return nil, err
			}
			sqlDocs[method] = *createdDoc
			changes[method] = didsubject.DIDChangeLog{
				DIDDocumentVersionID: createdDoc.ID,
				Type:                 didsubject.DIDChangeCreated,
				TransactionID:        transactionId,
				DIDDocumentVersion:   *createdDoc,
			}
		}
		return changes, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("could not store DID documents: %w", err)
	}

	docs := make([]did.Document, 0)
	for _, sqlDoc := range sqlDocs {
		doc, err := sqlDoc.ToDIDDocument()
		if err != nil {
			return nil, subject, err
		}
		docs = append(docs, doc)
	}
	return docs, subject, nil
}

func (r *Module) Deactivate(ctx context.Context, subject string) error {
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Debug("Deactivating DID Documents")

	err := r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]didsubject.DIDChangeLog, error) {
		changes := make(map[string]didsubject.DIDChangeLog)
		sqlDIDManager := didsubject.NewDIDManager(tx)
		sqlDIDDocumentManager := didsubject.NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return changes, err
		}
		if len(dids) == 0 {
			return nil, resolver.ErrNotFound
		}
		transactionID := uuid.New().String()
		for _, sqlDID := range dids {
			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, nil, nil)
			if err != nil {
				return changes, err
			}
			id, _ := did.ParseDID(sqlDID.ID)
			changes[id.Method] = didsubject.DIDChangeLog{
				DIDDocumentVersionID: sqlDoc.ID,
				Type:                 didsubject.DIDChangeDeactivated,
				TransactionID:        transactionID,
				DIDDocumentVersion:   *sqlDoc,
			}
		}
		return changes, nil
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

	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *didsubject.DIDDocument) (*didsubject.DIDDocument, error) {
		// use a generated ID where the fragment equals the hash of the service
		service.ID = GenerateIDForService(id, service)
		services = append(services, service)
		asJson, err := json.Marshal(service)
		if err != nil {
			return nil, err
		}
		sqlService := didsubject.SqlService{
			ID:            service.ID.String(),
			DIDDocumentID: current.DidID,
			Data:          asJson,
		}
		current.Services = append(current.Services, sqlService)
		return current, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not add service to DID Documents: %w", err)
	}

	return services, nil
}

func (r *Module) FindServices(_ context.Context, subject string, serviceType *string) ([]did.Service, error) {
	sqlDIDManager := didsubject.NewDIDManager(r.db)
	dids, err := sqlDIDManager.FindBySubject(subject)
	if err != nil {
		return nil, err
	}
	services := make([]did.Service, 0)
	// for detecting duplicates
	serviceMap := make(map[string]struct{})
	for _, sqlDID := range dids {
		id, _ := did.ParseDID(sqlDID.ID)
		current, err := didsubject.NewDIDDocumentManager(r.db).Latest(*id, nil)
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
	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *didsubject.DIDDocument) (*didsubject.DIDDocument, error) {
		j := 0
		for i, s := range current.Services {
			sID, _ := ssi.ParseURI(s.ID)
			if sID.Fragment == serviceID.Fragment {
				continue
			}
			current.Services[j] = current.Services[i]
			j++
		}
		current.Services = current.Services[:j]
		return current, nil
	})

	if err != nil {
		return fmt.Errorf("could not delete service from DID Documents: %w", err)
	}
	return nil
}

func (r *Module) UpdateService(ctx context.Context, subject string, serviceID ssi.URI, service did.Service) ([]did.Service, error) {
	services := make([]did.Service, 0)

	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *didsubject.DIDDocument) (*didsubject.DIDDocument, error) {
		j := 0
		for i, s := range current.Services {
			sID, _ := ssi.ParseURI(s.ID)
			if sID.Fragment == serviceID.Fragment {
				continue
			}
			current.Services[j] = current.Services[i]
			j++
		}
		current.Services = current.Services[:j]

		// use a generated ID where the fragment equals the hash of the service
		service.ID = GenerateIDForService(id, service)
		services = append(services, service)
		asJson, err := json.Marshal(service)
		if err != nil {
			return nil, err
		}
		sqlService := didsubject.SqlService{
			ID:            service.ID.String(),
			DIDDocumentID: current.DidID,
			Data:          asJson,
		}
		current.Services = append(current.Services, sqlService)
		return current, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not update service for DID Documents: %w", err)
	}
	return services, nil
}

func (r *Module) AddVerificationMethod(ctx context.Context, subject string, keyUsage didsubject.DIDKeyFlags) ([]did.VerificationMethod, error) {
	log.Logger().Debug("Creating new VerificationMethods.")

	verificationMethods := make([]did.VerificationMethod, 0)

	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *didsubject.DIDDocument) (*didsubject.DIDDocument, error) {
		vm, err := r.methodManagers[id.Method].NewVerificationMethod(ctx, id, keyUsage)
		if err != nil {
			return nil, err
		}
		verificationMethods = append(verificationMethods, *vm)
		data, _ := json.Marshal(*vm)
		sqlMethod := didsubject.VerificationMethod{
			ID:       vm.ID.String(),
			KeyTypes: didsubject.VerificationMethodKeyType(keyUsage),
			Data:     data,
		}
		current.VerificationMethods = append(current.VerificationMethods, sqlMethod)
		return current, nil
	})

	if err != nil {
		return nil, fmt.Errorf("could not update DID documents: %w", err)
	}
	return verificationMethods, nil
}

// transactionHelper is a helper function that starts a transaction, performs an operation, and emits an event.
func (r *Module) transactionHelper(ctx context.Context, operation func(tx *gorm.DB) (map[string]didsubject.DIDChangeLog, error)) error {
	var changes map[string]didsubject.DIDChangeLog
	var err error
	err = r.db.Transaction(func(tx *gorm.DB) error {
		// Perform the operation within the transaction.
		changes, err = operation(tx)
		if err != nil {
			return err
		}

		// Save all events
		for _, e := range changes {
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
	for method, manager := range r.methodManagers {
		err = manager.Commit(ctx, changes[method])
		if err != nil {
			break
		}
	}

	// in case of a DB failure, rollback/cleanup will be performed by the rollback loop.
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err != nil {
			// Delete the DID Document versions
			for _, change := range changes {
				// will also remove changelog via cascade
				err = tx.Where("id = ?", change.DIDDocumentVersionID).Delete(&didsubject.DIDDocument{}).Error
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (r *Module) applyToDIDDocuments(ctx context.Context, subject string, operation func(tx *gorm.DB, id did.DID, current *didsubject.DIDDocument) (*didsubject.DIDDocument, error)) error {
	return r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]didsubject.DIDChangeLog, error) {
		eventLog := make(map[string]didsubject.DIDChangeLog)
		sqlDIDManager := didsubject.NewDIDManager(tx)
		sqlDIDDocumentManager := didsubject.NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return nil, err
		}
		transactionID := uuid.New().String()
		for _, sqlDID := range dids {
			id, _ := did.ParseDID(sqlDID.ID)
			current, err := sqlDIDDocumentManager.Latest(*id, nil)
			if err != nil {
				return nil, err
			}
			next, err := operation(tx, *id, current)
			if err != nil {
				return nil, err
			}
			next, err = sqlDIDDocumentManager.CreateOrUpdate(current.DID, next.VerificationMethods, next.Services)
			if err != nil {
				return nil, err
			}
			eventLog[id.Method] = didsubject.DIDChangeLog{
				DIDDocumentVersionID: next.ID,
				Type:                 didsubject.DIDChangeUpdated,
				TransactionID:        transactionID,
				DIDDocumentVersion:   *next,
			}
		}
		return eventLog, nil
	})
}

func GenerateIDForService(id did.DID, service did.Service) ssi.URI {
	bytes, _ := json.Marshal(service)
	// go-did earlier unmarshaled/marshaled the service endpoint to a map[string]interface{} ("NormalizeDocument()"), which changes the order of the keys.
	// To retain the same hash given as before go-did v0.10.0, we need to mimic this behavior.
	var raw map[string]interface{}
	_ = json.Unmarshal(bytes, &raw)
	bytes, _ = json.Marshal(raw)
	shaBytes := sha256.Sum256(bytes)
	d := id.URI()
	d.Fragment = base58.EncodeAlphabet(shaBytes[:], base58.BTCAlphabet)
	return d
}
