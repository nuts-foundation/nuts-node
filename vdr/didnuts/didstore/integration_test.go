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

package didstore

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ordering(t *testing.T) {
	create := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	update := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	conflicted := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA, testServiceB}}
	conflictedBytes, _ := json.Marshal(conflicted)
	txCreate := newTestTransaction(create)
	txUpdate := newTestTransaction(update, txCreate.Ref)
	txUpdate.Clock = 1
	txUpdate.SigningTime = txCreate.SigningTime.Add(time.Second)

	t.Run("create", func(t *testing.T) {
		store := NewTestStore(t)
		add(t, store, create, txCreate)

		doc, meta, err := store.Resolve(testDID, nil)
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, txCreate.SigningTime.Unix(), meta.Created.Unix())
		assert.Equal(t, false, meta.Deactivated)
		assert.Equal(t, txCreate.PayloadHash, meta.Hash)
		assert.Nil(t, meta.PreviousHash)
		assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, meta.SourceTransactions)
		assert.Nil(t, meta.Updated)
		assert.Equal(t, create, *doc)
	})

	t.Run("create, update in order", func(t *testing.T) {
		store := NewTestStore(t)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		doc, meta, err := store.Resolve(testDID, nil)
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, txCreate.SigningTime.Unix(), meta.Created.Unix())
		assert.Equal(t, txUpdate.SigningTime.Unix(), meta.Updated.Unix())
		assert.Equal(t, false, meta.Deactivated)
		assert.Equal(t, txUpdate.PayloadHash, meta.Hash)
		assert.Equal(t, txCreate.PayloadHash, *meta.PreviousHash)
		assert.Equal(t, []hash.SHA256Hash{txUpdate.Ref}, meta.SourceTransactions)
		assert.Equal(t, update, *doc)
	})

	t.Run("create, update out of order", func(t *testing.T) {
		store := NewTestStore(t)
		add(t, store, update, txUpdate)
		add(t, store, create, txCreate)

		doc, meta, err := store.Resolve(testDID, nil)
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, txCreate.SigningTime.Unix(), meta.Created.Unix())
		assert.Equal(t, txUpdate.SigningTime.Unix(), meta.Updated.Unix())
		assert.Equal(t, false, meta.Deactivated)
		assert.Equal(t, txUpdate.PayloadHash, meta.Hash)
		assert.Equal(t, txCreate.PayloadHash, *meta.PreviousHash)
		assert.Equal(t, []hash.SHA256Hash{txUpdate.Ref}, meta.SourceTransactions)
		assert.Equal(t, update, *doc)
	})

	t.Run("conflict in order", func(t *testing.T) {
		store := NewTestStore(t)
		txUpdate := newTestTransaction(update)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		doc, meta, err := store.Resolve(testDID, nil)
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, txCreate.SigningTime.Unix(), meta.Created.Unix())
		assert.Equal(t, txUpdate.SigningTime.Unix(), meta.Updated.Unix())
		assert.Equal(t, false, meta.Deactivated)
		assert.Equal(t, hash.SHA256Sum(conflictedBytes), meta.Hash)
		assert.Equal(t, txCreate.PayloadHash, *meta.PreviousHash)
		assert.Equal(t, []hash.SHA256Hash{txUpdate.Ref, txCreate.Ref}, meta.SourceTransactions)
		assert.Equal(t, conflicted, *doc)
	})

	t.Run("conflict out of order", func(t *testing.T) {
		store := NewTestStore(t)
		txUpdate := newTestTransaction(update)
		add(t, store, update, txUpdate)
		add(t, store, create, txCreate)

		doc, meta, err := store.Resolve(testDID, nil)
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, txCreate.SigningTime.Unix(), meta.Created.Unix())
		assert.Equal(t, txUpdate.SigningTime.Unix(), meta.Updated.Unix())
		assert.Equal(t, false, meta.Deactivated)
		assert.Equal(t, hash.SHA256Sum(conflictedBytes), meta.Hash)
		assert.Equal(t, txCreate.PayloadHash, *meta.PreviousHash)
		assert.Equal(t, []hash.SHA256Hash{txUpdate.Ref, txCreate.Ref}, meta.SourceTransactions)
		assert.Equal(t, conflicted, *doc)
	})
}

func TestStore_deactivated(t *testing.T) {
	store := NewTestStore(t)
	create := did.Document{ID: testDID}
	tx := newTestTransaction(create)
	add(t, store, create, tx)

	t.Run("meta shows deactivated", func(t *testing.T) {
		doc, meta, err := store.Resolve(testDID, &resolver.ResolveMetadata{AllowDeactivated: true})
		require.NoError(t, err)

		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.True(t, meta.Deactivated)
	})
}

func TestStore_conflicted(t *testing.T) {
	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	doc2 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	tx1 := newTestTransaction(doc1)
	tx2 := newTestTransaction(doc2)

	t.Run("0 for empty store", func(t *testing.T) {
		store := NewTestStore(t)
		count, err := store.ConflictedCount()

		require.NoError(t, err)
		assert.Equal(t, uint(0), count)

		err = store.Conflicted(func(doc did.Document, metadata resolver.DocumentMetadata) error {
			t.Fail()
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("1 for conflict", func(t *testing.T) {
		store := NewTestStore(t)
		add(t, store, doc1, tx1)
		add(t, store, doc2, tx2)

		count, err := store.ConflictedCount()

		require.NoError(t, err)
		assert.Equal(t, uint(1), count)
		assert.Len(t, store.conflictedDocuments, 1)

		err = store.Conflicted(func(doc did.Document, metadata resolver.DocumentMetadata) error {
			assert.NotEqual(t, doc1, doc)
			assert.NotEqual(t, doc2, doc)
			assert.True(t, metadata.IsConflicted())
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("resolved", func(t *testing.T) {
		store := NewTestStore(t)
		tx3 := newTestTransaction(doc2, tx1.Ref, tx2.Ref)
		add(t, store, doc1, tx1)
		add(t, store, doc2, tx2)
		add(t, store, doc2, tx3)

		count, err := store.ConflictedCount()

		require.NoError(t, err)
		assert.Equal(t, uint(0), count)
		assert.Len(t, store.conflictedDocuments, 0)

		err = store.Conflicted(func(doc did.Document, metadata resolver.DocumentMetadata) error {
			t.Fail()
			return nil
		})
		require.NoError(t, err)
	})
}

func TestStore_duplicate(t *testing.T) {
	store := NewTestStore(t)
	create := did.Document{ID: testDID}
	tx := newTestTransaction(create)
	add(t, store, create, tx)
	add(t, store, create, tx)

	doc, meta, err := store.Resolve(testDID, &resolver.ResolveMetadata{AllowDeactivated: true})
	require.NoError(t, err)

	require.NotNil(t, doc)
	require.NotNil(t, meta)
	assert.False(t, meta.IsConflicted())
}

func TestStore_partialConflictResolve(t *testing.T) {
	// this test creates a conflict with A and B document updates
	// C only refers to B creating a new conflict between A and C
	// DID document data from B should not be present
	testServiceC := did.Service{ID: ssi.MustParseURI("did:nuts:service:c"), ServiceEndpoint: []interface{}{"http://c"}}
	docA := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	docB := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	docC := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceC}}
	txA := newTestTransaction(docA)
	txB := newTestTransaction(docB)
	txC := newTestTransaction(docC, txB.Ref)
	txC.Clock = 1
	txC.SigningTime = txB.SigningTime.Add(time.Second)

	store := NewTestStore(t)
	add(t, store, docA, txA)
	add(t, store, docB, txB)
	add(t, store, docC, txC)

	doc, meta, err := store.Resolve(testDID, nil)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotNil(t, meta)
	assert.Len(t, doc.Service, 2)
	assert.Equal(t, "did:nuts:service:a", doc.Service[0].ID.String())
	assert.Equal(t, "did:nuts:service:c", doc.Service[1].ID.String())
	assert.Equal(t, []hash.SHA256Hash{txC.Ref, txA.Ref}, meta.SourceTransactions)
}
