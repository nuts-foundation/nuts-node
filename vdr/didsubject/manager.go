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

package didsubject

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"gorm.io/gorm"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ErrSubjectAlreadyExists is returned when a subject already exists.
var ErrSubjectAlreadyExists = errors.New("subject already exists")

// ErrSubjectNotFound is returned when a subject is not found.
var ErrSubjectNotFound = errors.New("subject not found")

// subjectPattern is a regular expression for checking whether a subject follows the allowed pattern; a-z, 0-9, -, _, . (case insensitive)
var subjectPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

var _ SubjectManager = (*Manager)(nil)

type Manager struct {
	DB             *gorm.DB
	MethodManagers map[string]MethodManager
	KeyStore       nutsCrypto.KeyStore
	// PreferredOrder is the order in which the methods are preferred, which dictates the order in which they are returned.
	PreferredOrder []string
}

func (r *Manager) List(_ context.Context) (map[string][]did.DID, error) {
	sqlDIDManager := NewDIDManager(r.DB)
	dids, err := sqlDIDManager.All()
	if err != nil {
		return nil, err
	}
	result := make(map[string][]did.DID)
	for _, sqlDID := range dids {
		id, err := did.ParseDID(sqlDID.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid DID for subject (subject=%s, did=%s): %w", sqlDID.Subject, sqlDID.ID, err)
		}
		result[sqlDID.Subject] = append(result[sqlDID.Subject], *id)
	}
	for currentSubject := range result {
		sortDIDsByMethod(result[currentSubject], r.PreferredOrder)
	}
	return result, nil
}

func (r *Manager) ListDIDs(_ context.Context, subject string) ([]did.DID, error) {
	sqlDIDManager := NewDIDManager(r.DB)
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
	sortDIDsByMethod(result, r.PreferredOrder)
	return result, nil
}

func (r *Manager) Exists(_ context.Context, subject string) (bool, error) {
	sqlDIDManager := NewDIDManager(r.DB)
	return sqlDIDManager.SubjectExists(subject)
}

// Create generates new DID Documents
func (r *Manager) Create(ctx context.Context, options CreationOptions) ([]did.Document, string, error) {
	log.Logger().Debug("Creating new DID Documents.")

	// defaults
	keyFlags := orm.AssertionKeyUsage()
	subject := uuid.New().String()
	nutsLegacy := false

	// apply options
	for _, option := range options.All() {
		switch opt := option.(type) {
		case SubjectCreationOption:
			if !subjectPattern.MatchString(opt.Subject) {
				return nil, "", fmt.Errorf("invalid subject (must follow pattern: %s)", subjectPattern.String())
			}
			subject = opt.Subject
		case EncryptionKeyCreationOption:
			keyFlags = keyFlags | orm.EncryptionKeyUsage()
		case NutsLegacyNamingOption:
			nutsLegacy = true
		default:
			return nil, "", fmt.Errorf("unknown option: %T", option)
		}
	}

	sqlDocs := make(map[string]orm.DIDDocument)
	err := r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]orm.DIDChangeLog, error) {
		// check existence
		sqlDIDManager := NewDIDManager(tx)
		_, err := sqlDIDManager.FindBySubject(subject)
		if errors.Is(err, ErrSubjectNotFound) {
			// this is ok, doesn't exist yet
		} else if err != nil {
			// other error occurred
			return nil, err
		} else {
			return nil, ErrSubjectAlreadyExists
		}

		// call generate on all managers
		for method, manager := range r.MethodManagers {
			// save tx in context to pass all the way down to KeyStore
			transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
			sqlDoc, err := manager.NewDocument(transactionContext, keyFlags)
			if err != nil {
				return nil, fmt.Errorf("could not generate DID document (method %s): %w", method, err)
			}
			if nutsLegacy && method == "nuts" {
				subject = sqlDoc.DID.ID
			}
			sqlDocs[method] = *sqlDoc
		}

		alsoKnownAs := make([]orm.DID, 0)
		for _, sqlDoc := range sqlDocs {
			alsoKnownAs = append(alsoKnownAs, sqlDoc.DID)
		}

		// then store all docs in the sql db with matching events
		changes := make(map[string]orm.DIDChangeLog)
		sqlDIDDocumentManager := NewDIDDocumentManager(tx)
		transactionId := uuid.New().String()
		for method, sqlDoc := range sqlDocs {
			// overwrite sql.DID from returned document because we have the subject and alsoKnownAs here
			sqlDID := orm.DID{
				ID:      sqlDoc.DID.ID,
				Subject: subject,
				Aka:     alsoKnownAs,
			}
			createdDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, sqlDoc.VerificationMethods, nil)
			if err != nil {
				return nil, err
			}
			sqlDocs[method] = *createdDoc
			changes[method] = orm.DIDChangeLog{
				DIDDocumentVersionID: createdDoc.ID,
				Type:                 orm.DIDChangeCreated,
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
	var dids []string
	for _, sqlDoc := range sqlDocs {
		doc, err := sqlDoc.ToDIDDocument()
		if err != nil {
			return nil, subject, err
		}
		docs = append(docs, doc)
		dids = append(dids, sqlDoc.DID.ID)
	}
	sortDIDDocumentsByMethod(docs, r.PreferredOrder)
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Infof("Created new subject (DIDs: [%s])", strings.Join(dids, ", "))
	return docs, subject, nil
}

func (r *Manager) Deactivate(ctx context.Context, subject string) error {
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Debug("Deactivating DID Documents")

	err := r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]orm.DIDChangeLog, error) {
		changes := make(map[string]orm.DIDChangeLog)
		sqlDIDManager := NewDIDManager(tx)
		sqlDIDDocumentManager := NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return changes, err
		}
		transactionID := uuid.New().String()
		for _, sqlDID := range dids {
			sqlDoc, err := sqlDIDDocumentManager.CreateOrUpdate(sqlDID, nil, nil)
			if err != nil {
				return changes, err
			}
			id, _ := did.ParseDID(sqlDID.ID)
			changes[id.Method] = orm.DIDChangeLog{
				DIDDocumentVersionID: sqlDoc.ID,
				Type:                 orm.DIDChangeDeactivated,
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
func (r *Manager) CreateService(ctx context.Context, subject string, service did.Service) ([]did.Service, error) {
	services := make([]did.Service, 0)

	serviceIDFragment := NewIDForService(service)
	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *orm.DIDDocument) (*orm.DIDDocument, error) {
		// use a generated ID where the fragment equals the hash of the service
		service.ID = id.URI()
		service.ID.Fragment = serviceIDFragment
		// return values
		services = append(services, service)
		// check if service already exists
		for _, s := range current.Services {
			sID, _ := ssi.ParseURI(s.ID)
			if sID.Fragment == serviceIDFragment {
				return nil, nil
			}
		}
		asJson, err := json.Marshal(service)
		if err != nil {
			return nil, err
		}
		sqlService := orm.Service{
			ID:   service.ID.String(),
			Data: asJson,
		}
		current.Services = append(current.Services, sqlService)

		return current, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not add service to DID Documents: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Infof("Created new service for subject (type: %s, id: %s)", service.Type, service.ID)
	return services, nil
}

func (r *Manager) FindServices(_ context.Context, subject string, serviceType *string) ([]did.Service, error) {
	sqlDIDManager := NewDIDManager(r.DB)
	dids, err := sqlDIDManager.FindBySubject(subject)
	if err != nil {
		return nil, err
	}
	services := make([]did.Service, 0)
	// for detecting duplicates
	serviceMap := make(map[string]struct{})
	for _, sqlDID := range dids {
		id, _ := did.ParseDID(sqlDID.ID)
		current, err := NewDIDDocumentManager(r.DB).Latest(*id, nil)
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
func (r *Manager) DeleteService(ctx context.Context, subject string, serviceID ssi.URI) error {
	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *orm.DIDDocument) (*orm.DIDDocument, error) {
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
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Infof("Deleted service for subject (id: %s)", serviceID.String())
	return nil
}

func (r *Manager) UpdateService(ctx context.Context, subject string, serviceID ssi.URI, service did.Service) ([]did.Service, error) {
	services := make([]did.Service, 0)

	// use a generated ID where the fragment equals the hash of the service
	serviceIDFragment := NewIDForService(service)
	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *orm.DIDDocument) (*orm.DIDDocument, error) {
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

		service.ID = id.URI()
		service.ID.Fragment = serviceIDFragment
		services = append(services, service)
		asJson, err := json.Marshal(service)
		if err != nil {
			return nil, err
		}
		sqlService := orm.Service{
			ID:   service.ID.String(),
			Data: asJson,
		}
		current.Services = append(current.Services, sqlService)
		return current, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not update service for DID Documents: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Infof("Updated service for subject (id: %s)", serviceID.String())
	return services, nil
}

func (r *Manager) AddVerificationMethod(ctx context.Context, subject string, keyUsage orm.DIDKeyFlags) ([]did.VerificationMethod, error) {
	log.Logger().Debug("Creating new VerificationMethods.")

	verificationMethods := make([]did.VerificationMethod, 0)
	var vmIDs []string
	err := r.applyToDIDDocuments(ctx, subject, func(tx *gorm.DB, id did.DID, current *orm.DIDDocument) (*orm.DIDDocument, error) {
		// known limitation
		if keyUsage.Is(orm.KeyAgreementUsage) && id.Method == "web" {
			return nil, errors.New("key agreement not supported for did:web")
			// todo requires update to nutsCrypto module
			//verificationMethodKey, err = m.keyStore.NewRSA(ctx, func(key crypt.PublicKey) (string, error) {
			//	return verificationMethodID.String(), nil
			//})
		}

		transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
		vm, err := r.MethodManagers[id.Method].NewVerificationMethod(transactionContext, id, keyUsage)
		if err != nil {
			return nil, err
		}
		verificationMethods = append(verificationMethods, *vm)
		data, _ := json.Marshal(*vm)
		sqlMethod := orm.VerificationMethod{
			ID:       vm.ID.String(),
			KeyTypes: orm.VerificationMethodKeyType(keyUsage),
			Data:     data,
		}
		current.VerificationMethods = append(current.VerificationMethods, sqlMethod)
		vmIDs = append(vmIDs, vm.ID.String())
		return current, nil
	})

	if err != nil {
		return nil, fmt.Errorf("could not update DID documents: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldDIDSubject, subject).
		Infof("Added verification method for subject (IDs: [%s])", strings.Join(vmIDs, ", "))
	return verificationMethods, nil
}

// transactionHelper is a helper function that starts a transaction, performs an operation, and emits an event.
func (r *Manager) transactionHelper(ctx context.Context, operation func(tx *gorm.DB) (map[string]orm.DIDChangeLog, error)) error {
	var changes map[string]orm.DIDChangeLog
	if err := r.DB.Transaction(func(tx *gorm.DB) error {
		var operationErr error
		// Perform the operation within the transaction.
		changes, operationErr = operation(tx)
		if operationErr != nil {
			return operationErr
		}

		// Save all events
		for _, e := range changes {
			operationErr = tx.Save(&e).Error
			if operationErr != nil {
				return operationErr
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Call commit for all managers on the created docs
	var errManager error
	for method, manager := range r.MethodManagers {
		if change, ok := changes[method]; ok {
			errManager = manager.Commit(ctx, change)
			if errManager != nil {
				break
			}
		}
	}

	// in case of a DB failure, rollback/cleanup will be performed by the rollback loop.
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		if errManager != nil {
			// Delete the DID Document versions
			for _, change := range changes {
				// will also remove changelog via cascade
				if err := tx.Where("id = ?", change.DIDDocumentVersionID).Delete(&orm.DIDDocument{}).Error; err != nil {
					return err
				}
			}
		} else {
			// delete all changes
			for _, change := range changes {
				if err := tx.Where("transaction_id = ?", change.TransactionID).Delete(&orm.DIDChangeLog{}).Error; err != nil {
					return err
				}
				// once is enough
				break
			}
		}
		return nil
	})
	// give priority to the DB error (critical)
	if err != nil {
		return err
	}
	// then functional error
	return errManager
}

// applyToDIDDocuments is a helper function that applies an operation to all DID documents of a subject (1 per did method).
// It uses transactionHelper to perform the operation in a transaction.
// if the operation returns nil then no changes are made.
func (r *Manager) applyToDIDDocuments(ctx context.Context, subject string, operation func(tx *gorm.DB, id did.DID, current *orm.DIDDocument) (*orm.DIDDocument, error)) error {
	return r.transactionHelper(ctx, func(tx *gorm.DB) (map[string]orm.DIDChangeLog, error) {
		eventLog := make(map[string]orm.DIDChangeLog)
		sqlDIDManager := NewDIDManager(tx)
		sqlDIDDocumentManager := NewDIDDocumentManager(tx)
		dids, err := sqlDIDManager.FindBySubject(subject)
		if err != nil {
			return nil, err
		}
		transactionID := uuid.New().String()
		for _, sqlDID := range dids {
			id, err := did.ParseDID(sqlDID.ID)
			if err != nil {
				return nil, err
			}
			current, err := sqlDIDDocumentManager.Latest(*id, nil)
			if err != nil {
				return nil, err
			}
			next, err := operation(tx, *id, current)
			if err != nil {
				return nil, err
			}
			if next != nil {
				next, err = sqlDIDDocumentManager.CreateOrUpdate(current.DID, next.VerificationMethods, next.Services)
				if err != nil {
					return nil, err
				}
				eventLog[id.Method] = orm.DIDChangeLog{
					DIDDocumentVersionID: next.ID,
					Type:                 orm.DIDChangeUpdated,
					TransactionID:        transactionID,
					DIDDocumentVersion:   *next,
				}
			}
		}
		return eventLog, nil
	})
}

// NewIDForService generates a unique ID for a service based on the service data.
// This is compatible with all DID methods.
func NewIDForService(service did.Service) string {
	bytes, _ := json.Marshal(service)
	// go-did earlier unmarshaled/marshaled the service endpoint to a map[string]interface{} ("NormalizeDocument()"), which changes the order of the keys.
	// To retain the same hash given as before go-did v0.10.0, we need to mimic this behavior.
	var raw map[string]interface{}
	_ = json.Unmarshal(bytes, &raw)
	bytes, _ = json.Marshal(raw)
	shaBytes := sha256.Sum256(bytes)
	return base58.EncodeAlphabet(shaBytes[:], base58.BTCAlphabet)
}

// Rollback queries the did_change_log table for all changes that are older than 1 minute.
// Any entry that's still there is considered not committed and will be rolled back.
// All DID Document versions that are part of the same transaction_id will be deleted.
// This works because did:web is always committed and did:nuts might not be. So the DB state actually only depends on the result of the did:nuts network operation result.
func (r *Manager) Rollback(ctx context.Context) {
	updatedAt := time.Now().Add(-time.Minute).Unix()
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		changes := make([]orm.DIDChangeLog, 0)
		groupedChanges := make(map[string][]orm.DIDChangeLog)
		// find all DIDChangeLog inner join with DIDDocumentVersion where document.updated_at < now - 1 minute
		// note: any changes to this query needs to manually be tested in all supported DBs
		err := tx.Preload("DIDDocumentVersion").Preload("DIDDocumentVersion.DID").InnerJoins("DIDDocumentVersion", tx.Where("updated_at < ?", updatedAt)).Find(&changes).Error
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
				committed, err = r.MethodManagers[change.Method()].IsCommitted(ctx, change)
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
					err := tx.Where("id = ?", change.DIDDocumentVersionID).Delete(&orm.DIDDocument{}).Error
					if err != nil {
						return err
					}
				}
			}
			// delete all changes, also done via cascading in case of !committed, but less code this way
			err = tx.Where("transaction_id = ?", transactionID).Delete(&orm.DIDChangeLog{}).Error
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

func sortDIDsByMethod(list []did.DID, methodOrder []string) {
	sort.Slice(list, func(i, j int) bool {
		// if the DIDs are the same, use string compare
		if list[i] == list[j] {
			return list[i].String() < list[j].String()
		}

		iOrder := -1
		jOrder := -1
		for k, v := range methodOrder {
			if v == list[i].Method {
				iOrder = k
			}
			if v == list[j].Method {
				jOrder = k
			}
		}
		// If both are -1, they are not in the preferred methodOrder list, so sort by method for stable methodOrder
		if iOrder == -1 && jOrder == -1 {
			return list[i].Method < list[j].Method
		}
		return iOrder < jOrder
	})
}

// sortDIDDocumentsByMethod sorts a list of DID documents by the methods of their ID, according to the given order.
func sortDIDDocumentsByMethod(list []did.Document, methodOrder []string) {
	listOfDIDs := make([]did.DID, len(list))
	for i, doc := range list {
		listOfDIDs[i] = doc.ID
	}
	sortDIDsByMethod(listOfDIDs, methodOrder)
	// methodOrder list according to listOfDIDs
	orderedList := make([]did.Document, len(list))
	for i, id := range listOfDIDs {
	inner:
		for _, doc := range list {
			if doc.ID == id {
				orderedList[i] = doc
				break inner
			}
		}
	}
	copy(list, orderedList)
}
