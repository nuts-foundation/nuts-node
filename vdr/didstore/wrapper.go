package didstore

import (
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

func NewDeferredStore(provider storage.Provider) Store {
	return &deferredStore{
		provider: provider,
	}
}

type deferredStore struct {
	underlyingStore Store
	provider        storage.Provider
}

func (tl *deferredStore) Configure(_ core.ServerConfig) error {
	sqlDB := tl.provider.GetSQLStore()
	if sqlDB != nil {
		didStore, err := NewSQLStore(sqlDB)
		if err != nil {
			return fmt.Errorf("failed to create SQL store: %w", err)
		}
		tl.underlyingStore = didStore
	} else {
		tl.underlyingStore = New(tl.provider)
	}
	return nil
}

func (d deferredStore) Add(didDocument did.Document, transaction Transaction) error {
	return d.underlyingStore.Add(didDocument, transaction)
}

func (d deferredStore) Conflicted(fn types.DocIterator) error {
	return d.underlyingStore.Conflicted(fn)
}

func (d deferredStore) ConflictedCount() (uint, error) {
	return d.underlyingStore.ConflictedCount()
}

func (d deferredStore) DocumentCount() (uint, error) {
	return d.underlyingStore.DocumentCount()
}

func (d deferredStore) Iterate(fn types.DocIterator) error {
	return d.underlyingStore.Iterate(fn)
}

func (d deferredStore) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	return d.underlyingStore.Resolve(id, metadata)
}
