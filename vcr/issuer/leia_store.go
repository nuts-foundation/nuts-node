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
	"fmt"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

const issuedBackupShelf = "credentials"
const revocationBackupShelf = "revocations"

// leiaIssuerStore implements the issuer Store interface. It is a simple and fast JSON store.
// Note: It can not be used in a clustered setup.
type leiaIssuerStore struct {
	store storage.KVBackedLeiaStore
}

// NewLeiaIssuerStore creates a new instance of leiaIssuerStore which implements the Store interface.
func NewLeiaIssuerStore(dbPath string, backupStore stoabs.KVStore) (Store, error) {
	store, err := leia.NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaIssuerStore: %w", err)
	}
	// add backup wrapper
	kvBackedStore, err := storage.NewKVBackedLeiaStore(store, backupStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create KV backed issuer store: %w", err)
	}

	// set backup config
	kvBackedStore.AddConfiguration(storage.LeiaBackupConfiguration{
		CollectionName: "issuedCredentials",
		CollectionType: leia.JSONCollection,
		BackupShelf:    issuedBackupShelf,
		SearchQuery:    leia.NewJSONPath("id"),
	})
	kvBackedStore.AddConfiguration(storage.LeiaBackupConfiguration{
		CollectionName: "revokedCredentials",
		CollectionType: leia.JSONCollection,
		BackupShelf:    revocationBackupShelf,
		SearchQuery:    leia.NewJSONPath(credential.RevocationSubjectPath),
	})

	newLeiaStore := &leiaIssuerStore{
		store: kvBackedStore,
	}

	// initialize indices, this is required for handleRestore. Without the index metadata it can't iterate and detect data entries.
	if err = newLeiaStore.createIssuedIndices(); err != nil {
		return nil, err
	}
	if err = newLeiaStore.createRevokedIndices(); err != nil {
		return nil, err
	}

	if err = kvBackedStore.HandleRestore(); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaIssuerStore) StoreCredential(vc vc.VerifiableCredential) error {
	vcAsBytes, _ := json.Marshal(vc)
	return s.issuedCollection().Add([]leia.Document{vcAsBytes})
}

func (s leiaIssuerStore) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath("issuer"), leia.MustParseScalar(issuer.String()))).
		And(leia.Eq(leia.NewJSONPath("type"), leia.MustParseScalar(credentialType.String())))

	if subject != nil {
		if subjectString := subject.String(); subjectString != "" {
			query = query.And(leia.Eq(leia.NewJSONPath(credential.CredentialSubjectPath), leia.MustParseScalar(subjectString)))
		}
	}

	docs, err := s.issuedCollection().Find(context.Background(), query)
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

	results, err := s.issuedCollection().Find(context.Background(), query)
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
	return s.revokedCollection().Add([]leia.Document{revocationAsBytes})
}

func (s leiaIssuerStore) GetRevocation(subject ssi.URI) (*credential.Revocation, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath(credential.RevocationSubjectPath), leia.MustParseScalar(subject.String())))

	results, err := s.revokedCollection().Find(context.Background(), query)
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

func (s leiaIssuerStore) issuedCollection() leia.Collection {
	return s.store.Collection(leia.JSONCollection, "issuedCredentials")
}

func (s leiaIssuerStore) revokedCollection() leia.Collection {
	return s.store.Collection(leia.JSONCollection, "revokedCredentials")
}

// createIssuedIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaIssuerStore) createIssuedIndices() error {
	searchIndex := s.issuedCollection().NewIndex("issuedVCs",
		leia.NewFieldIndexer(leia.NewJSONPath("issuer")),
		leia.NewFieldIndexer(leia.NewJSONPath("type")),
		leia.NewFieldIndexer(leia.NewJSONPath("credentialSubject.id")),
	)

	// Index used for getting issued VCs by id
	idIndex := s.issuedCollection().NewIndex("issuedVCByID",
		leia.NewFieldIndexer(leia.NewJSONPath("id")))
	return s.issuedCollection().AddIndex(searchIndex, idIndex)
}

// createRevokedIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaIssuerStore) createRevokedIndices() error {
	// Index used for getting issued VCs by id
	revocationBySubjectIDIndex := s.revokedCollection().NewIndex("revocationBySubjectIDIndex",
		leia.NewFieldIndexer(leia.NewJSONPath(credential.RevocationSubjectPath)))
	return s.revokedCollection().AddIndex(revocationBySubjectIDIndex)
}

func (s leiaIssuerStore) Diagnostics() []core.DiagnosticResult {
	var err error
	var issuedCredentialCount int
	issuedCredentialCount, err = s.issuedCollection().DocumentCount()
	if err != nil {
		issuedCredentialCount = -1
		log.Logger().
			WithError(err).
			Warn("unable to retrieve issuedCredentials document count")
	}
	var revokedCredentialsCount int
	revokedCredentialsCount, err = s.revokedCollection().DocumentCount()
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
