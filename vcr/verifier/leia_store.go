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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// leiaVerifierStore implements the verifier Store interface. It is a simple and fast JSON store.
// Note: It can not be used in a clustered setup.
type leiaVerifierStore struct {
	// revocations is a leia collection containing all the revocations
	revocations leia.Collection
	store       leia.Store
}

// NewLeiaVerifierStore creates a new instance of leiaVerifierStore which implements the Store interface.
func NewLeiaVerifierStore(dbPath string) (Store, error) {
	store, err := leia.NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaVerifierStore: %w", err)
	}
	revocations := store.Collection(leia.JSONCollection, "revocations")
	newLeiaStore := &leiaVerifierStore{
		revocations: revocations,
		store:       store,
	}
	if err := newLeiaStore.createIndices(revocations); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaVerifierStore) StoreRevocation(revocation credential.Revocation) error {
	revocationAsBytes, _ := json.Marshal(revocation)
	return s.revocations.Add([]leia.Document{revocationAsBytes})
}

func (s leiaVerifierStore) GetRevocations(id ssi.URI) ([]*credential.Revocation, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath(credential.RevocationSubjectPath), leia.MustParseScalar(id.String())))

	results, err := s.revocations.Find(context.Background(), query)
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

// createIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaVerifierStore) createIndices(collection leia.Collection) error {
	// Index used for getting issued VCs by id
	revocationBySubjectIDIndex := collection.NewIndex("revocationBySubjectIDIndex",
		leia.NewFieldIndexer(leia.NewJSONPath(credential.RevocationSubjectPath)))
	return s.revocations.AddIndex(revocationBySubjectIDIndex)
}

func (s leiaVerifierStore) Diagnostics() []core.DiagnosticResult {
	var count int
	var err error
	count, err = s.revocations.DocumentCount()
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
