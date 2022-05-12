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
	"fmt"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// leiaIssuerStore implements the issuer Store interface. It is a simple and fast JSON store.
// Note: It can not be used in a clustered setup.
type leiaIssuerStore struct {
	issuedCredentials  leia.Collection
	revokedCredentials leia.Collection
	store              leia.Store
}

// NewLeiaIssuerStore creates a new instance of leiaIssuerStore which implements the Store interface.
func NewLeiaIssuerStore(dbPath string) (Store, error) {
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
	}
	if err := newLeiaStore.createIssuedIndices(issuedCollection); err != nil {
		return nil, err
	}
	if err := newLeiaStore.createRevokedIndices(revokedCollection); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaIssuerStore) StoreCredential(vc vc.VerifiableCredential) error {
	vcAsBytes, _ := json.Marshal(vc)
	return s.issuedCredentials.Add([]leia.Document{vcAsBytes})
}

func (s leiaIssuerStore) SearchCredential(jsonLDContext ssi.URI, credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath("issuer"), leia.MustParseScalar(issuer.String()))).
		And(leia.Eq(leia.NewJSONPath("type"), leia.MustParseScalar(credentialType.String()))).
		And(leia.Eq(leia.NewJSONPath("@context"), leia.MustParseScalar(jsonLDContext.String())))

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
		return nil, ErrNotFound
	}
	if len(results) > 1 {
		return nil, ErrMultipleFound
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
	return s.revokedCredentials.Add([]leia.Document{revocationAsBytes})
}

func (s leiaIssuerStore) GetRevocation(id ssi.URI) (*credential.Revocation, error) {
	query := leia.New(leia.Eq(leia.NewJSONPath(credential.RevocationSubjectPath), leia.MustParseScalar(id.String())))

	results, err := s.revokedCredentials.Find(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("error while getting revocation by id: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	if len(results) > 1 {
		return nil, ErrMultipleFound
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
