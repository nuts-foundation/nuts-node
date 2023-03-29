/*
 * Copyright (C) 2022 Nuts community
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

package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

const issuedBackupShelf = "credentials"
const revocationBackupShelf = "revocations"

// leiaIssuerStore implements the issuer Store interface. It is a simple and fast JSON store.
// Note: It can not be used in a clustered setup.
type leiaIssuerStore struct {
	issuedCredentials  leia.Collection
	revokedCredentials leia.Collection
	store              leia.Store
	backupStore        stoabs.KVStore
}

// NewLeiaIssuerStore creates a new instance of leiaIssuerStore which implements the Store interface.
func NewLeiaIssuerStore(dbPath string, backupStore stoabs.KVStore) (Store, error) {
	store, err := leia.NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaIssuerStore: %w", err)
	}
	issuedCollection := store.JSONCollection("issuedCredentials")
	revokedCollection := store.JSONCollection("revokedCredentials")
	newLeiaStore := &leiaIssuerStore{
		issuedCredentials:  issuedCollection,
		revokedCredentials: revokedCollection,
		store:              store,
		backupStore:        backupStore,
	}

	// initialize indices, this is required for handleRestore. Without the index metadata it can't iterate and detect data entries.
	if err = newLeiaStore.createIssuedIndices(issuedCollection); err != nil {
		return nil, err
	}
	if err = newLeiaStore.createRevokedIndices(revokedCollection); err != nil {
		return nil, err
	}

	// handle backup/restore for issued credentials
	if err = newLeiaStore.handleRestore(issuedCollection, issuedBackupShelf, "id"); err != nil {
		return nil, err
	}
	// handle backup/restore for revocations
	if err = newLeiaStore.handleRestore(revokedCollection, revocationBackupShelf, credential.RevocationSubjectPath); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaIssuerStore) StoreCredential(vc vc.VerifiableCredential) error {
	vcAsBytes, _ := json.Marshal(vc)
	ref := s.issuedCredentials.Reference(vcAsBytes)

	// first in backup
	if err := s.backupStore.WriteShelf(context.Background(), issuedBackupShelf, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(ref), vcAsBytes)
	}); err != nil {
		return err
	}

	// then in index
	return s.issuedCredentials.Add([]leia.Document{vcAsBytes})
}

func (s leiaIssuerStore) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath("issuer"), leia.MustParseScalar(issuer.String()))).
		And(leia.Eq(leia.NewJSONPath("type"), leia.MustParseScalar(credentialType.String())))

	if subject != nil {
		if subjectString := subject.String(); subjectString != "" {
			query = query.And(leia.Eq(leia.NewJSONPath(credential.CredentialSubjectPath), leia.MustParseScalar(subjectString)))
		}
	}

	docs, err := s.issuedCredentials.Find(context.Background(), query)
	if err != nil {
		return nil, err
	}

	result := make([]vc.VerifiableCredential, len(docs))
	for i, doc := range docs {
		if err := json.Unmarshal(doc, &result[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s leiaIssuerStore) GetCredential(id ssi.URI) (*vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath("id"), leia.MustParseScalar(id.String())))

	results, err := s.issuedCredentials.Find(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("could not get credential by id: %w", err)
	}
	if len(results) == 0 {
		return nil, types.ErrNotFound
	}
	if len(results) > 1 {
		return nil, types.ErrMultipleFound
	}
	result := results[0]
	credential := &vc.VerifiableCredential{}
	if err := json.Unmarshal(result, credential); err != nil {
		return credential, err
	}
	return credential, nil
}

func (s leiaIssuerStore) StoreRevocation(revocation credential.Revocation) error {
	revocationAsBytes, _ := json.Marshal(revocation)
	ref := s.revokedCredentials.Reference(revocationAsBytes)

	// first in backup
	if err := s.backupStore.WriteShelf(context.Background(), revocationBackupShelf, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(ref), revocationAsBytes)
	}); err != nil {
		return err
	}

	// then in index
	return s.revokedCredentials.Add([]leia.Document{revocationAsBytes})
}

func (s leiaIssuerStore) GetRevocation(subject ssi.URI) (*credential.Revocation, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath(credential.RevocationSubjectPath), leia.MustParseScalar(subject.String())))

	results, err := s.revokedCredentials.Find(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("error while getting revocation by id: %w", err)
	}
	if len(results) == 0 {
		return nil, types.ErrNotFound
	}
	if len(results) > 1 {
		return nil, types.ErrMultipleFound
	}
	result := results[0]
	revocation := &credential.Revocation{}
	if err := json.Unmarshal(result, revocation); err != nil {
		return nil, err
	}

	return revocation, nil
}

func (s leiaIssuerStore) Close() error {
	return s.store.Close()
}

// handleRestore checks if both the leiaDB store is present and if the backup store is present.
// If the backup store is empty, it'll create it from the leia store.
// If the leia store is empty, it'll fill it from the backup store.
// If both are empty, do nothing.
func (s leiaIssuerStore) handleRestore(collection leia.Collection, backupShelf string, jsonSearchPath string) error {
	backupPresent := s.backupStorePresent(backupShelf)
	storePresent := storePresent(collection, jsonSearchPath)

	if backupPresent && storePresent {
		// both are filled => normal operation, done
		return nil
	}

	if !backupPresent && !storePresent {
		// both are non-existent => empty node, done
		return nil
	}

	if !storePresent {
		log.Logger().
			WithField(core.LogFieldStoreShelf, backupShelf).
			Info("Missing index for shelf, rebuilding")
		// empty node, backup has been restored, refill store
		return s.backupStore.ReadShelf(context.Background(), backupShelf, func(reader stoabs.Reader) error {
			return reader.Iterate(func(key stoabs.Key, value []byte) error {
				return collection.Add([]leia.Document{value})
			}, stoabs.BytesKey{})
		})
	}

	log.Logger().
		WithField(core.LogFieldStoreShelf, backupShelf).
		Info("Missing store for shelf, creating from index")

	// else !backupPresent, process per 100
	query := leia.New(leia.NotNil(leia.NewJSONPath(jsonSearchPath)))

	const limit = 100
	type refDoc struct {
		ref leia.Reference
		doc leia.Document
	}
	var set []refDoc
	writeDocuments := func(set []refDoc) error {
		return s.backupStore.Write(context.Background(), func(tx stoabs.WriteTx) error {
			writer := tx.GetShelfWriter(backupShelf)
			for _, entry := range set {
				if err := writer.Put(stoabs.BytesKey(entry.ref), entry.doc); err != nil {
					return err
				}
			}
			set = make([]refDoc, 0)
			return nil
		})
	}

	err := collection.Iterate(query, func(ref leia.Reference, value []byte) error {
		set = append(set, refDoc{ref: ref, doc: value})
		if len(set) >= limit {
			return writeDocuments(set)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(set) > 0 {
		return writeDocuments(set)
	}
	return nil
}

func (s leiaIssuerStore) backupStorePresent(backupShelf string) bool {
	backupPresent := false

	_ = s.backupStore.ReadShelf(context.Background(), backupShelf, func(reader stoabs.Reader) error {
		isEmpty, err := reader.Empty()
		backupPresent = !isEmpty
		return err
	})

	return backupPresent
}

func storePresent(collection leia.Collection, jsonSearchPath string) bool {
	issuedPresent := false
	// to check if any entries are in the DB, we iterate over the index and stop when the first item is found
	query := leia.New(leia.NotNil(leia.NewJSONPath(jsonSearchPath)))
	_ = collection.IndexIterate(query, func(key []byte, value []byte) error {
		issuedPresent = true
		return errors.New("exit")
	})

	return issuedPresent
}

// createIssuedIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaIssuerStore) createIssuedIndices(collection leia.Collection) error {
	searchIndex := collection.NewIndex("issuedVCs",
		leia.NewFieldIndexer(leia.NewJSONPath("issuer")),
		leia.NewFieldIndexer(leia.NewJSONPath("type")),
		leia.NewFieldIndexer(leia.NewJSONPath("credentialSubject.id")),
	)

	// Index used for getting issued VCs by id
	idIndex := collection.NewIndex("issuedVCByID",
		leia.NewFieldIndexer(leia.NewJSONPath("id")))
	return s.issuedCredentials.AddIndex(searchIndex, idIndex)
}

// createRevokedIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaIssuerStore) createRevokedIndices(collection leia.Collection) error {
	// Index used for getting issued VCs by id
	revocationBySubjectIDIndex := collection.NewIndex("revocationBySubjectIDIndex",
		leia.NewFieldIndexer(leia.NewJSONPath(credential.RevocationSubjectPath)))
	return s.revokedCredentials.AddIndex(revocationBySubjectIDIndex)
}

func (s leiaIssuerStore) Diagnostics() []core.DiagnosticResult {
	var err error
	var issuedCredentialCount int
	issuedCredentialCount, err = s.issuedCredentials.DocumentCount()
	if err != nil {
		issuedCredentialCount = -1
		log.Logger().
			WithError(err).
			Warn("unable to retrieve issuedCredentials document count")
	}
	var revokedCredentialsCount int
	revokedCredentialsCount, err = s.revokedCredentials.DocumentCount()
	if err != nil {
		revokedCredentialsCount = -1
		log.Logger().
			WithError(err).
			Warn("unable to retrieve revokedCredentials document count")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "issued_credentials_count",
			Outcome: issuedCredentialCount,
		},
		core.GenericDiagnosticResult{
			Title:   "revoked_credentials_count",
			Outcome: revokedCredentialsCount,
		},
	}
}
