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

package verifier

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/log"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

const revocationBackupShelf = "revocations"

// leiaVerifierStore implements the verifier Store interface. It is a simple and fast JSON store.
// Note: It can not be used in a clustered setup.
type leiaVerifierStore struct {
	store storage.KVBackedLeiaStore
}

// NewLeiaVerifierStore creates a new instance of leiaVerifierStore which implements the Store interface.
func NewLeiaVerifierStore(dbPath string, backupStore stoabs.KVStore) (Store, error) {
	store, err := leia.NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaVerifierStore: %w", err)
	}

	// add backup wrapper
	kvBackedStore, err := storage.NewKVBackedLeiaStore(store, backupStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create KV backed issuer store: %w", err)
	}

	// set backup config
	kvBackedStore.AddConfiguration(storage.LeiaBackupConfiguration{
		CollectionName: "revocations",
		CollectionType: leia.JSONCollection,
		BackupShelf:    revocationBackupShelf,
		SearchQuery:    leia.NewJSONPath(credential.RevocationSubjectPath),
	})

	newLeiaStore := &leiaVerifierStore{
		store: kvBackedStore,
	}
	if err = newLeiaStore.createIndices(); err != nil {
		return nil, err
	}

	if err = kvBackedStore.HandleRestore(); err != nil {
		return nil, err
	}

	return newLeiaStore, nil
}

func (s leiaVerifierStore) StoreRevocation(revocation credential.Revocation) error {
	revocationAsBytes, _ := json.Marshal(revocation)
	return s.revocationCollection().Add([]leia.Document{revocationAsBytes})
}

func (s leiaVerifierStore) GetRevocations(id ssi.URI) ([]*credential.Revocation, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath(credential.RevocationSubjectPath), leia.MustParseScalar(id.String())))

	results, err := s.revocationCollection().Find(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("error while getting revocation by id: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}

	revocations := make([]*credential.Revocation, len(results))
	for i, result := range results {
		revocation := &credential.Revocation{}
		if err := json.Unmarshal(result, revocation); err != nil {
			return nil, err
		}
		revocations[i] = revocation
	}

	return revocations, nil
}

func (s leiaVerifierStore) Close() error {
	return s.store.Close()
}

func (s leiaVerifierStore) revocationCollection() leia.Collection {
	return s.store.Collection(leia.JSONCollection, "revocations")
}

// createIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaVerifierStore) createIndices() error {
	// Index used for getting issued VCs by id
	revocationBySubjectIDIndex := s.revocationCollection().NewIndex("revocationBySubjectIDIndex",
		leia.NewFieldIndexer(leia.NewJSONPath(credential.RevocationSubjectPath)))
	return s.revocationCollection().AddIndex(revocationBySubjectIDIndex)
}

func (s leiaVerifierStore) Diagnostics() []core.DiagnosticResult {
	var count int
	var err error
	count, err = s.revocationCollection().DocumentCount()
	if err != nil {
		count = -1
		log.Logger().
			WithError(err).
			Warn("unable to retrieve revocations document count")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "revocations_count",
			Outcome: count,
		},
	}
}
