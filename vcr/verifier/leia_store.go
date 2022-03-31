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

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
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
	store, err := leia.NewStore(dbPath, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaVerifierStore: %w", err)
	}
	revocations := store.Collection("revocations")
	newLeiaStore := &leiaVerifierStore{
		revocations: revocations,
		store:       store,
	}
	if err := newLeiaStore.createIndices(); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaVerifierStore) StoreRevocation(revocation credential.Revocation) error {
	revocationAsBytes, _ := json.Marshal(revocation)
	doc := leia.DocumentFromBytes(revocationAsBytes)
	return s.revocations.Add([]leia.Document{doc})
}

func (s leiaVerifierStore) GetRevocations(id ssi.URI) ([]*credential.Revocation, error) {
	query := leia.New(leia.Eq(concept.SubjectField, id.String()))

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
		if err := json.Unmarshal(result.Bytes(), revocation); err != nil {
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
func (s leiaVerifierStore) createIndices() error {
	// Index used for getting issued VCs by id
	revocationBySubjectIDIndex := leia.NewIndex("revocationBySubjectIDIndex",
		leia.NewFieldIndexer("subject"))
	return s.revocations.AddIndex(revocationBySubjectIDIndex)
}
