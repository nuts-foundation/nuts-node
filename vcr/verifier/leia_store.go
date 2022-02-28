package verifier

import (
	"context"
	"encoding/json"
	"errors"
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

func (s leiaVerifierStore) GetRevocation(id ssi.URI) (*credential.Revocation, error) {
	query := leia.New(leia.Eq(concept.SubjectField, id.String()))

	results, err := s.revocations.Find(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("error while getting revocation by id: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	if len(results) > 1 {
		return nil, errors.New("found more than one revocation by id")
	}
	result := results[0]
	revocation := &credential.Revocation{}
	if err := json.Unmarshal(result.Bytes(), revocation); err != nil {
		return revocation, err
	}
	return revocation, nil
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
