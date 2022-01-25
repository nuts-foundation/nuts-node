/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package store

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

func newBBoltTestStore(t *testing.T) *bboltStore {
	opts := *bbolt.DefaultOptions
	opts.NoSync = true

	dir, err := ioutil.TempDir("/tmp", "go_test_vdr_bboltstore")
	assert.NoError(t, err)

	db, err := bbolt.Open(filepath.Join(dir, "bbolt.db"), 0644, &opts)
	assert.NoError(t, err)

	return NewBBoltStore(db).(*bboltStore)
}

func TestBBoltStore_Write(t *testing.T) {
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
	}
	meta := types.DocumentMetadata{}

	err := store.Write(doc, meta)

	t.Run("returns no error on successful write", func(t *testing.T) {
		assert.NoError(t, err)
	})

	t.Run("doesn't return an error when already exist", func(t *testing.T) {
		err := store.Write(doc, meta)
		assert.NoError(t, err)
	})
}

func TestBBoltStore_Resolve(t *testing.T) {
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID:         *did1,
		Controller: []did.DID{*did1},
	}

	firstHash, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4619")
	txHash := hash.FromSlice([]byte("keyTransactionHash"))
	firstMeta := types.DocumentMetadata{
		Created:            time.Now().Add(time.Hour * -48),
		Hash:               firstHash,
		SourceTransactions: []hash.SHA256Hash{txHash},
	}

	err := store.Write(doc, firstMeta)
	assert.NoError(t, err)

	latestHash, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	meta := types.DocumentMetadata{
		Created:            time.Now().Add(time.Hour * -24),
		Hash:               latestHash,
		SourceTransactions: []hash.SHA256Hash{txHash},
	}

	err = store.Update(*did1, firstHash, doc, &meta)
	assert.NoError(t, err)

	t.Run("returns ErrNotFound on unknown did", func(t *testing.T) {
		did2, _ := did.ParseDID("did:nuts:2")
		_, _, err := store.Resolve(*did2, nil)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("returns the last document without resolve metadata", func(t *testing.T) {
		d, m, err := store.Resolve(*did1, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, d)
		assert.NotNil(t, m)
		assert.Equal(t, m.Hash, latestHash)
	})

	t.Run("returns document with resolve metadata - selection on date", func(t *testing.T) {
		now := time.Now()
		d, m, err := store.Resolve(*did1, &types.ResolveMetadata{
			ResolveTime: &now,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, d)
		assert.NotNil(t, m)
	})

	t.Run("returns no document with resolve metadata - selection on date", func(t *testing.T) {
		before := time.Now().Add(time.Hour * -48)
		_, _, err := store.Resolve(*did1, &types.ResolveMetadata{
			ResolveTime: &before,
		})
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("returns document with resolve metadata - selection on hash", func(t *testing.T) {
		d, m, err := store.Resolve(*did1, &types.ResolveMetadata{
			Hash: &firstHash,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, d)
		assert.NotNil(t, m)
	})

	t.Run("returns document with resolve metadata - selection on KeyTransaction", func(t *testing.T) {
		d, m, err := store.Resolve(*did1, &types.ResolveMetadata{
			SourceTransaction: &txHash,
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, d)
		assert.NotNil(t, m)
	})

	t.Run("returns no document with resolve metadata - selection on KeyTransaction", func(t *testing.T) {
		_, _, err := store.Resolve(*did1, &types.ResolveMetadata{
			SourceTransaction: &latestHash,
		})
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestBBoltStore_TimeSelectionFilter(t *testing.T) {
	earlier := time.Now().Add(time.Hour * -24)
	now := time.Now()
	later := time.Now().Add(time.Hour * 24)

	metadata := types.ResolveMetadata{
		ResolveTime: &now,
	}
	f := timeSelectionFilter(metadata)

	t.Run("returns false when created later", func(t *testing.T) {
		entry := memoryEntry{
			metadata: types.DocumentMetadata{
				Created: later,
			},
		}
		assert.False(t, f(entry))
	})

	t.Run("returns true when created earlier", func(t *testing.T) {
		entry := memoryEntry{
			metadata: types.DocumentMetadata{
				Created: earlier,
			},
		}
		assert.True(t, f(entry))
	})

	t.Run("returns false when next document was updated earlier", func(t *testing.T) {
		entry := memoryEntry{
			metadata: types.DocumentMetadata{
				Created: earlier,
				Updated: &earlier,
			},
			next: &memoryEntry{
				metadata: types.DocumentMetadata{
					Created: earlier,
					Updated: &earlier,
				},
			},
		}
		assert.False(t, f(entry))
	})

	t.Run("returns false when document was updated later", func(t *testing.T) {
		entry := memoryEntry{
			metadata: types.DocumentMetadata{
				Created: earlier,
				Updated: &later,
			},
		}
		assert.False(t, f(entry))
	})
}

func TestBBoltStore_Update(t *testing.T) {
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID:         *did1,
		Controller: []did.DID{*did1},
	}
	h, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	meta := types.DocumentMetadata{
		Hash: h,
	}

	_ = store.Write(doc, meta)

	t.Run("returns no error on success", func(t *testing.T) {
		err := store.Update(*did1, h, doc, &meta)
		assert.NoError(t, err)
	})

	t.Run("returns no error on duplicate update", func(t *testing.T) {
		err := store.Update(*did1, h, doc, &meta)
		if !assert.NoError(t, err) {
			return
		}
		err = store.Update(*did1, h, doc, &meta)
		if !assert.NoError(t, err) {
			return
		}

		// check version
		_, m, err := store.Resolve(*did1, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, m.PreviousHash)
		assert.Equal(t, h, m.Hash)
	})

	t.Run("updates the previous record", func(t *testing.T) {
		later := time.Now().Add(time.Hour * 24)
		meta = types.DocumentMetadata{
			Hash:    h,
			Created: time.Now(),
			Updated: &later,
		}
		err := store.Update(*did1, h, doc, &meta)
		assert.NoError(t, err)

		//s := store.(*memory)
		//assert.NotNil(t, s.store[did1.String()][0].next)
	})

	t.Run("returns error when DID document doesn't exist", func(t *testing.T) {
		did1, _ := did.ParseDID("did:nuts:2")
		err := store.Update(*did1, h, doc, &meta)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("returns error when hashes don't match", func(t *testing.T) {
		h, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4621")
		err := store.Update(*did1, h, doc, &meta)
		assert.Equal(t, types.ErrUpdateOnOutdatedData, err)
	})

	t.Run("returns error when DID Document is deactivated", func(t *testing.T) {
		did1, _ := did.ParseDID("did:nuts:2")
		doc := did.Document{
			ID: *did1,
		}
		err := store.Write(doc, meta)
		if !assert.NoError(t, err) {
			return
		}

		err = store.Update(*did1, h, doc, &meta)
		assert.Equal(t, types.ErrDeactivated, err)
	})
}

func TestBBoltStore_Parallelism(t *testing.T) {
	// This test, when run with -race, assures access to internals is synchronized
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	did2, _ := did.ParseDID("did:nuts:2")
	doc := did.Document{
		ID: *did1,
	}
	doc2 := did.Document{
		ID: *did2,
	}
	meta := types.DocumentMetadata{}

	// Make sure update, resolve and iterate have something to work on
	_ = store.Write(doc, meta)

	// Prepare functions to be called
	wg := sync.WaitGroup{}
	funcs := []func(){
		func() {
			_ = store.Write(doc2, meta)
		},
		func() {
			_ = store.Iterate(func(_ did.Document, _ types.DocumentMetadata) error {
				return nil
			})
		},
		func() {
			_ = store.Update(*did1, hash.EmptyHash(), doc, &meta)
		},
		func() {
			_, _, _ = store.Resolve(*did1, nil)
		},
	}
	wg.Add(len(funcs))

	// Execute functions and wait for them to finish
	for _, fn := range funcs {
		go func(actual func()) {
			actual()
			wg.Done()
		}(fn)
	}
	wg.Wait()
}

func TestBBoltStore_Iterate(t *testing.T) {
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
	}
	meta := types.DocumentMetadata{}
	counter := func(count *int) types.DocIterator {
		return func(doc did.Document, metadata types.DocumentMetadata) error {
			*count++
			return nil
		}
	}

	t.Run("no hits", func(t *testing.T) {
		count := 0
		fn := counter(&count)

		err := store.Iterate(fn)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, 0, count)
	})

	t.Run("hit", func(t *testing.T) {
		_ = store.Write(doc, meta)
		count := 0
		fn := counter(&count)

		err := store.Iterate(fn)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, 1, count)
	})

	t.Run("error", func(t *testing.T) {
		fn := func(doc did.Document, metadata types.DocumentMetadata) error {
			return errors.New("b00m!")
		}

		err := store.Iterate(fn)

		assert.Error(t, err)
	})
}

func TestBBoltStore_DeactivatedFilter(t *testing.T) {
	store := newBBoltTestStore(t)
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
	}
	h, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	meta := types.DocumentMetadata{
		Hash: h,
	}

	_ = store.Write(doc, meta)

	t.Run("returns error when document is deactivated", func(t *testing.T) {
		_, _, err := store.Resolve(*did1, nil)
		assert.ErrorIs(t, types.ErrDeactivated, err)
	})

	t.Run("returns deactivated document when allow deactivated is enabled in metadata", func(t *testing.T) {
		result, _, err := store.Resolve(*did1, &types.ResolveMetadata{AllowDeactivated: true})
		assert.NoError(t, err)
		assert.Equal(t, doc, *result)
	})
}
