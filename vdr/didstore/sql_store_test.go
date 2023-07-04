/*
 * Copyright (C) 2023 Nuts community
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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

var docACreate did.Document
var docACreateTx Transaction
var docAUpdate did.Document
var docAUpdateTx Transaction
var docBCreate did.Document
var docBCreateTx Transaction

func init() {
	docACreate = did.Document{ID: testDID, Controller: []did.DID{testDID}}
	docACreateTx = newTestTransaction(docACreate)
	docAUpdate = did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{{ID: ssi.MustParseURI("service")}}}
	docAUpdateTx = newTestTransaction(docAUpdate, docACreateTx.Ref)
	docAUpdateTx.SigningTime = docACreateTx.SigningTime
	docACreateTx.SigningTime = docACreateTx.SigningTime.Add(-2 * time.Second)
	didB := did.MustParseDID("did:nuts:didB")
	docBCreate = did.Document{ID: didB, Controller: []did.DID{didB}}
	docBCreateTx = newTestTransaction(docBCreate)
}

func TestSqlStore_Add(t *testing.T) {

	store := newTestSqlStore(t)

	t.Run("one version", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docACreate, docACreateTx)
		require.NoError(t, err)

		// count = 1
		count, err := store.DocumentCount()
		require.NoError(t, err)
		assert.Equal(t, uint(1), count)

		// resolve
		_, md, err := store.Resolve(testDID, nil)
		require.NoError(t, err)
		assert.Equal(t, docACreateTx.Ref, md.SourceTransactions[0])
		assert.Nil(t, md.PreviousHash)
	})

	t.Run("update in order", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docACreate, docACreateTx)
		require.NoError(t, err)
		err = store.Add(docAUpdate, docAUpdateTx)
		require.NoError(t, err)

		// count = 1
		count, err := store.DocumentCount()
		require.NoError(t, err)
		assert.Equal(t, uint(1), count)

		// resolve = updated version
		_, md, err := store.Resolve(testDID, nil)
		require.NoError(t, err)
		assert.Equal(t, docAUpdateTx.Ref, md.SourceTransactions[0])
	})

	t.Run("update out order", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docAUpdate, docAUpdateTx)
		require.NoError(t, err)

		// resolve = updated version
		_, md, err := store.Resolve(testDID, nil)
		require.NoError(t, err)
		assert.Equal(t, docAUpdateTx.Ref, md.SourceTransactions[0])

		// Now add initial created document
		err = store.Add(docACreate, docACreateTx)
		require.NoError(t, err)

		// count = 1
		count, err := store.DocumentCount()
		require.NoError(t, err)
		assert.Equal(t, uint(1), count)

		// resolve = updated version
		_, md, err = store.Resolve(testDID, nil)
		require.NoError(t, err)
		assert.Equal(t, docAUpdateTx.Ref, md.SourceTransactions[0])
	})

	t.Run("duplicate should be ignored", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docACreate, docACreateTx)
		require.NoError(t, err)
		err = store.Add(docACreate, docACreateTx)
		require.NoError(t, err)

		// count = 1
		count, err := store.DocumentCount()
		require.NoError(t, err)
		assert.Equal(t, uint(1), count)
	})

	t.Run("conflicted", func(t *testing.T) {
		// Tests a conflicted document, 2 versions of the same DID.
		// - Add() should succeed
		// - ConflictedCount() should return 1
		// - Resolve() should return the merged version
		resetSqlStore(t, store)

		doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
		doc2 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
		tx1 := newTestTransaction(doc1)
		tx2 := newTestTransaction(doc2)

		err := store.Add(doc1, tx1)
		require.NoError(t, err)
		err = store.Add(doc2, tx2)
		require.NoError(t, err)

		conflictedCount, err := store.ConflictedCount()
		require.NoError(t, err)
		assert.Equal(t, uint(1), conflictedCount)

		actual, md, err := store.Resolve(testDID, nil)
		require.NoError(t, err)
		assert.Equal(t, testDID, actual.ID)
		assert.Equal(t, []did.Service{testServiceA, testServiceB}, actual.Service)
		assert.Equal(t, []hash.SHA256Hash{tx1.Ref, tx2.Ref}, md.SourceTransactions)
	})

	//t.Run("create ok", func(t *testing.T) {
	//	require.NoError(t, store.Add(create, txCreate))
	//
	//	t.Run("metadata ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
	//			metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s0", testDID.String())))
	//			if err != nil {
	//				return err
	//			}
	//			metadata := documentMetadata{}
	//			err = json.Unmarshal(metaBytes, &metadata)
	//			if err != nil {
	//				return err
	//			}
	//
	//			assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
	//			assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Updated.Unix())
	//			assert.Nil(t, metadata.PreviousHash)
	//			assert.Equal(t, txCreate.PayloadHash, metadata.Hash)
	//			assert.Nil(t, metadata.PreviousTransaction)
	//			assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.SourceTransactions)
	//			assert.Equal(t, 0, metadata.Version)
	//			assert.Equal(t, false, metadata.Deactivated)
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//
	//	t.Run("document ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), documentShelf, func(reader stoabs.Reader) error {
	//			bytes, err := reader.Get(stoabs.HashKey(txCreate.PayloadHash))
	//			if err != nil {
	//				return err
	//			}
	//			document := did.Document{}
	//			err = json.Unmarshal(bytes, &document)
	//			if err != nil {
	//				return err
	//			}
	//
	//			assert.Equal(t, create, document)
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//
	//	t.Run("latest ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), latestShelf, func(reader stoabs.Reader) error {
	//			bytes, err := reader.Get(stoabs.BytesKey(testDID.String()))
	//			if err != nil {
	//				return err
	//			}
	//			assert.Equal(t, fmt.Sprintf("%s0", testDID.String()), string(bytes))
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//})
	//
	//t.Run("duplicate ok", func(t *testing.T) {
	//	store := NewTestStore(t)
	//
	//	require.NoError(t, store.Add(create, txCreate))
	//	require.NoError(t, store.Add(create, txCreate))
	//
	//	err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
	//		metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s0", testDID.String())))
	//		if err != nil {
	//			return err
	//		}
	//		metadata := documentMetadata{}
	//		err = json.Unmarshal(metaBytes, &metadata)
	//		if err != nil {
	//			return err
	//		}
	//
	//		assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
	//		assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Updated.Unix())
	//		assert.Nil(t, metadata.PreviousHash)
	//		assert.Equal(t, txCreate.PayloadHash, metadata.Hash)
	//		assert.Nil(t, metadata.PreviousTransaction)
	//		assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.SourceTransactions)
	//		assert.Equal(t, 0, metadata.Version)
	//		assert.Equal(t, false, metadata.Deactivated)
	//
	//		return nil
	//	})
	//	require.NoError(t, err)
	//})
	//
	//t.Run("update ok", func(t *testing.T) {
	//	store := NewTestStore(t)
	//
	//	require.NoError(t, store.Add(update, docAUpdateTx))
	//	require.NoError(t, store.Add(create, txCreate))
	//
	//	t.Run("metadata ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
	//			metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s1", testDID.String())))
	//			if err != nil {
	//				return err
	//			}
	//			metadata := documentMetadata{}
	//			err = json.Unmarshal(metaBytes, &metadata)
	//			if err != nil {
	//				return err
	//			}
	//
	//			assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
	//			assert.Equal(t, docAUpdateTx.SigningTime.Unix(), metadata.Updated.Unix())
	//			require.NotNil(t, metadata.PreviousHash)
	//			assert.Equal(t, txCreate.PayloadHash, *metadata.PreviousHash)
	//			assert.Equal(t, docAUpdateTx.PayloadHash, metadata.Hash)
	//			assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.PreviousTransaction)
	//			assert.Equal(t, []hash.SHA256Hash{docAUpdateTx.Ref}, metadata.SourceTransactions)
	//			assert.Equal(t, 1, metadata.Version)
	//			assert.Equal(t, false, metadata.Deactivated)
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//
	//	t.Run("document ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), documentShelf, func(reader stoabs.Reader) error {
	//			bytes, err := reader.Get(stoabs.HashKey(txCreate.PayloadHash))
	//			if err != nil {
	//				return err
	//			}
	//			document := did.Document{}
	//			err = json.Unmarshal(bytes, &document)
	//			if err != nil {
	//				return err
	//			}
	//
	//			assert.Equal(t, create, document)
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//
	//	t.Run("latest ok", func(t *testing.T) {
	//		err := store.db.ReadShelf(context.Background(), latestShelf, func(reader stoabs.Reader) error {
	//			bytes, err := reader.Get(stoabs.BytesKey(testDID.String()))
	//			if err != nil {
	//				return err
	//			}
	//			assert.Equal(t, fmt.Sprintf("%s1", testDID.String()), string(bytes))
	//
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	})
	//})
}

func TestSqlStore_Conflicted(t *testing.T) {
	store := newTestSqlStore(t)

	didA := did.MustParseDID("did:nuts:A")
	didB := did.MustParseDID("did:nuts:B")

	didADoc1 := did.Document{ID: didA, Controller: []did.DID{didA}, Service: []did.Service{testServiceA}}
	didADoc2 := did.Document{ID: didA, Controller: []did.DID{didA}, Service: []did.Service{testServiceB}}

	didBDoc1 := did.Document{ID: didB, Controller: []did.DID{didB}, Service: []did.Service{testServiceA}}
	didBDoc2 := did.Document{ID: didB, Controller: []did.DID{didB}, Service: []did.Service{testServiceB}}

	err := store.Add(didADoc1, newTestTransaction(didADoc1))
	require.NoError(t, err)
	err = store.Add(didADoc2, newTestTransaction(didADoc2))
	require.NoError(t, err)
	err = store.Add(didBDoc1, newTestTransaction(didBDoc1))
	require.NoError(t, err)
	err = store.Add(didBDoc2, newTestTransaction(didBDoc2))
	require.NoError(t, err)

	t.Run("count", func(t *testing.T) {
		count, err := store.ConflictedCount()
		require.NoError(t, err)
		assert.Equal(t, uint(2), count)
	})
}

func TestSqlStore_Lifecycle(t *testing.T) {
	t.Run("migrate with existing tables", func(t *testing.T) {
		store := newTestSqlStore(t)
		err := store.migrate()
		require.NoError(t, err)
	})
}

func TestSqlStore_Iterate(t *testing.T) {
	store := newTestSqlStore(t)

	// Populate store with 2 DIDs, A has 1 version, B has 2 versions.
	// Iterate should walk over 2 documents (only the latest versions).
	didA := did.MustParseDID("did:nuts:A")
	didB := did.MustParseDID("did:nuts:B")
	didADoc1 := did.Document{ID: didA, Controller: []did.DID{didA}, Service: []did.Service{testServiceA}}
	didBDoc1 := did.Document{ID: didB, Controller: []did.DID{didB}, Service: []did.Service{testServiceA}}
	didBDoc2 := did.Document{ID: didB, Controller: []did.DID{didB}, Service: []did.Service{testServiceB}}
	err := store.Add(didADoc1, newTestTransaction(didADoc1))
	require.NoError(t, err)
	didBDoc1TX := newTestTransaction(didBDoc1)
	err = store.Add(didBDoc1, didBDoc1TX)
	require.NoError(t, err)
	err = store.Add(didBDoc2, newTestTransaction(didBDoc2, didBDoc1TX.Ref))
	require.NoError(t, err)

	var docs []did.Document
	err = store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		docs = append(docs, doc)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, docs, 2)
	assert.Contains(t, docs, didADoc1)
	assert.Contains(t, docs, didBDoc2)
}

func Test_sqlStore_DocumentCount(t *testing.T) {
	store := newTestSqlStore(t)
	t.Run("only returns unique documents", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docACreate, docACreateTx)
		require.NoError(t, err)
		err = store.Add(docAUpdate, docAUpdateTx)
		require.NoError(t, err)
		err = store.Add(docBCreate, docBCreateTx)
		require.NoError(t, err)

		count, err := store.DocumentCount()

		require.NoError(t, err)
		assert.Equal(t, uint(2), count)
	})
	t.Run("empty store returns 0", func(t *testing.T) {
		resetSqlStore(t, store)

		count, err := store.DocumentCount()

		require.NoError(t, err)
		assert.Equal(t, uint(0), count)
	})
}

func TestSqlStore_Resolve(t *testing.T) {
	store := newTestSqlStore(t)

	var deactivatedDID = did.MustParseDID("did:nuts:deactivated")
	deactivatedDoc := did.Document{ID: deactivatedDID}
	err := store.Add(deactivatedDoc, newTestTransaction(deactivatedDoc))
	require.NoError(t, err)

	err = store.Add(docACreate, docACreateTx)
	require.NoError(t, err)
	err = store.Add(docAUpdate, docAUpdateTx)

	t.Run("not found", func(t *testing.T) {
		_, _, err := store.Resolve(did.MustParseDID("did:nuts:unknown"), nil)

		assert.ErrorIs(t, err, types.ErrNotFound)
	})
	t.Run("latest", func(t *testing.T) {
		doc, meta, err := store.Resolve(testDID, nil)

		require.NoError(t, err)
		assert.Len(t, doc.Service, 1)
		assert.Equal(t, docAUpdateTx.PayloadHash, meta.Hash)
		// TODO: PreviousHash
		//assert.NotNil(t, meta.PreviousHash)
	})
	t.Run("deactivated DIDs", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			doc, md, err := store.Resolve(deactivatedDID, &types.ResolveMetadata{AllowDeactivated: true})
			require.NoError(t, err)
			assert.Equal(t, deactivatedDoc, *doc)
			assert.NotNil(t, md)
		})
		t.Run("not allowed", func(t *testing.T) {
			doc, md, err := store.Resolve(deactivatedDID, nil)
			assert.ErrorIs(t, err, types.ErrDeactivated)
			assert.Nil(t, doc)
			assert.Nil(t, md)
		})
	})
	t.Run("filter on SourceTransaction", func(t *testing.T) {
		t.Run("resolve first version", func(t *testing.T) {
			doc, meta, err := store.Resolve(testDID, &types.ResolveMetadata{SourceTransaction: &docACreateTx.Ref})

			require.NoError(t, err)
			assert.Len(t, doc.Service, 0)
			assert.Equal(t, docACreateTx.PayloadHash, meta.Hash)
		})
		t.Run("resolve second version", func(t *testing.T) {
			doc, meta, err := store.Resolve(testDID, &types.ResolveMetadata{SourceTransaction: &docAUpdateTx.Ref})

			require.NoError(t, err)
			assert.Len(t, doc.Service, 1)
			assert.Equal(t, docAUpdateTx.PayloadHash, meta.Hash)
		})
		t.Run("does not resolve for different DID", func(t *testing.T) {
			doc, meta, err := store.Resolve(did.MustParseDID("did:nuts:other"), &types.ResolveMetadata{SourceTransaction: &docAUpdateTx.Ref})

			require.ErrorIs(t, err, types.ErrNotFound)
			assert.Nil(t, doc)
			assert.Nil(t, meta)
		})
	})

	//
	//	t.Run("previous", func(t *testing.T) {
	//		before := docAUpdateTx.SigningTime.Add(-1 * time.Second)
	//		doc, meta, err := store.Resolve(testDID, &types.ResolveMetadata{ResolveTime: &before})
	//
	//		require.NoError(t, err)
	//		assert.Len(t, doc.Service, 0)
	//		assert.Nil(t, meta.PreviousHash)
	//	})
	//
	//	t.Run("to far back", func(t *testing.T) {
	//		before := docAUpdateTx.SigningTime.Add(-3 * time.Second)
	//		_, _, err := store.Resolve(testDID, &types.ResolveMetadata{ResolveTime: &before})
	//
	//		assert.Equal(t, types.ErrNotFound, err)
	//	})
	//
	//	t.Run("deactivated", func(t *testing.T) {
	//		store := NewTestStore(t)
	//		update := did.Document{ID: testDID}
	//		docAUpdateTx := newTestTransaction(update, txCreate.Ref)
	//		add(t, store, create, txCreate)
	//		add(t, store, update, docAUpdateTx)
	//
	//		_, _, err := store.Resolve(testDID, nil)
	//
	//		assert.Equal(t, types.ErrDeactivated, err)
	//	})
	//
	//	t.Run("deactivated, but specifically asking for !allowDeactivated", func(t *testing.T) {
	//		store := NewTestStore(t)
	//		update := did.Document{ID: testDID}
	//		docAUpdateTx := newTestTransaction(update, txCreate.Ref)
	//		add(t, store, create, txCreate)
	//		add(t, store, update, docAUpdateTx)
	//
	//		_, _, err := store.Resolve(testDID, &types.ResolveMetadata{})
	//
	//		assert.Equal(t, types.ErrDeactivated, err)
	//	})
	//}

	//	func TestStore_Iterate(t *testing.T) {
	//		store := NewTestStore(t)
	//
	//		document := did.Document{ID: testDID}
	//		transaction := newTestTransaction(document)
	//		add(t, store, document, transaction)
	//
	//		err := store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
	//			assert.Equal(t, document, doc)
	//			assert.Equal(t, []hash.SHA256Hash{transaction.Ref}, metadata.SourceTransactions)
	//			return nil
	//		})
	//		require.NoError(t, err)
	//	}
	//
	//	func TestStore_ConflictedCount(t *testing.T) {
	//		store := NewTestStore(t)
	//		doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	//		doc2 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	//		tx1 := newTestTransaction(doc1)
	//		tx2 := newTestTransaction(doc2)
	//		add(t, store, doc1, tx1)
	//		add(t, store, doc2, tx2)
	//
	//		t.Run("stats are written", func(t *testing.T) {
	//			err := store.db.ReadShelf(context.Background(), statsShelf, func(reader stoabs.Reader) error {
	//				cBytes, _ := reader.Get(stoabs.BytesKey(conflictedCountKey))
	//				require.True(t, len(cBytes) > 0)
	//				assert.Equal(t, uint32(1), binary.BigEndian.Uint32(cBytes))
	//
	//				return nil
	//			})
	//			require.NoError(t, err)
	//		})
	//
	//		t.Run("conflictedShelf is written", func(t *testing.T) {
	//			count := 0
	//			err := store.db.ReadShelf(context.Background(), conflictedShelf, func(reader stoabs.Reader) error {
	//				return reader.Iterate(func(key stoabs.Key, value []byte) error {
	//					count++
	//					assert.Equal(t, testDID.String(), string(key.Bytes()))
	//
	//					return nil
	//				}, stoabs.BytesKey{})
	//			})
	//			require.NoError(t, err)
	//			assert.Equal(t, 1, count)
	//		})
}

func Test_sqlStore_Conflicted(t *testing.T) {
	store := newTestSqlStore(t)
	t.Run("no conflicts", func(t *testing.T) {
		resetSqlStore(t, store)

		err := store.Add(docACreate, docACreateTx)
		require.NoError(t, err)

		count := 0
		err = store.Conflicted(func(_ did.Document, _ types.DocumentMetadata) error {
			count++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
	t.Run("conflicts", func(t *testing.T) {
		resetSqlStore(t, store)

		// Conflicted document
		doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
		doc2 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
		tx1 := newTestTransaction(doc1)
		tx2 := newTestTransaction(doc2)

		err := store.Add(doc1, tx1)
		require.NoError(t, err)
		err = store.Add(doc2, tx2)
		require.NoError(t, err)

		// Some other, non-conflicted document
		err = store.Add(docBCreate, docBCreateTx)
		require.NoError(t, err)

		var conflicts []did.DID
		err = store.Conflicted(func(doc did.Document, _ types.DocumentMetadata) error {
			conflicts = append(conflicts, doc.ID)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, []did.DID{testDID}, conflicts)
	})
	t.Run("empty store", func(t *testing.T) {
		resetSqlStore(t, store)

		count := 0
		err := store.Conflicted(func(_ did.Document, _ types.DocumentMetadata) error {
			count++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

func TestSqlStore_DocumentCount(t *testing.T) {
	store := newTestSqlStore(t)
	t.Run("empty store", func(t *testing.T) {
		resetSqlStore(t, store)

		count, err := store.DocumentCount()
		require.NoError(t, err)
		assert.Equal(t, uint(0), count)
	})

	//	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	//	tx1 := newTestTransaction(doc1)
	//
	//	t.Run("ok for 0", func(t *testing.T) {
	//		store := NewTestStore(t)
	//
	//		count, err := store.DocumentCount()
	//
	//		require.NoError(t, err)
	//		assert.Equal(t, uint(0), count)
	//	})
	//
	//	t.Run("ok for > 0", func(t *testing.T) {
	//		store := NewTestStore(t)
	//		add(t, store, doc1, tx1)
	//
	//		count, err := store.DocumentCount()
	//
	//		require.NoError(t, err)
	//		assert.Equal(t, uint(1), count)
	//	})
}

//
//func TestStore_Redis(t *testing.T) {
//	// This test uses github.com/alicebob/miniredis/v2
//	// A separate test for redis is required, because redis does not have transaction isolation
//	// go-stoabs writes all changes to redis on commit, any read during the transaction will read old/stale data.
//	redisServer := miniredis.RunT(t)
//	redisClient, err := redis7.CreateRedisStore("db", &redis.Options{
//		Addr: redisServer.Addr(),
//	})
//	require.NoError(t, err)
//	store := New(nil).(*store)
//	store.db = redisClient
//	create := did.Document{ID: testDID, Controller: []did.DID{testDID}}
//	txCreate := newTestTransaction(create)
//
//	err = store.Add(create, txCreate)
//
//	assert.NoError(t, err)
//}
//
//func Test_matches(t *testing.T) {
//	now := time.Now()
//	h := hash.RandomHash()
//	h2 := hash.RandomHash()
//	metadata := documentMetadata{
//		Created:            now.Add(-4 * time.Second),
//		Updated:            now.Add(-2 * time.Second),
//		Hash:               h,
//		SourceTransactions: []hash.SHA256Hash{h},
//		Deactivated:        false,
//	}
//	deactivated := metadata
//	deactivated.Deactivated = true
//
//	t.Run("true", func(t *testing.T) {
//		t.Run("time", func(t *testing.T) {
//			resolveTime := now.Add(-1 * time.Second)
//
//			assert.True(t, matches(metadata, &types.ResolveMetadata{ResolveTime: &resolveTime}))
//		})
//		t.Run("no resolveMetadata", func(t *testing.T) {
//			assert.True(t, matches(metadata, nil))
//		})
//		t.Run("empty resolveMetadata", func(t *testing.T) {
//			assert.True(t, matches(metadata, &types.ResolveMetadata{}))
//		})
//		t.Run("deactivated", func(t *testing.T) {
//			assert.True(t, matches(deactivated, &types.ResolveMetadata{AllowDeactivated: true}))
//		})
//		t.Run("source transaction", func(t *testing.T) {
//			assert.True(t, matches(metadata, &types.ResolveMetadata{SourceTransaction: &h}))
//		})
//		t.Run("hash", func(t *testing.T) {
//			assert.True(t, matches(metadata, &types.ResolveMetadata{Hash: &h}))
//		})
//	})
//	t.Run("false", func(t *testing.T) {
//		t.Run("time", func(t *testing.T) {
//			resolveTime := now.Add(-3 * time.Second)
//
//			assert.False(t, matches(metadata, &types.ResolveMetadata{ResolveTime: &resolveTime}))
//		})
//		t.Run("no meta and deactivated", func(t *testing.T) {
//			assert.False(t, matches(deactivated, nil))
//		})
//		t.Run("hash", func(t *testing.T) {
//			assert.False(t, matches(metadata, &types.ResolveMetadata{Hash: &h2}))
//		})
//		t.Run("source transaction", func(t *testing.T) {
//			assert.False(t, matches(metadata, &types.ResolveMetadata{SourceTransaction: &h2}))
//		})
//	})
//}

func newTestSqlStore(t *testing.T) *sqlStore {
	db, err := storage.CreateSQLDatabase(t)
	require.NoError(t, err)
	s, err := NewSQLStore(db)
	require.NoError(t, err)
	return s.(*sqlStore)
}

func resetSqlStore(t *testing.T, store *sqlStore) {
	t.Cleanup(func() {
		_, err := store.db.Exec("DELETE FROM did_prevs")
		if err != nil {
			panic(err)
		}
		_, err = store.db.Exec("DELETE FROM did_documents")
		if err != nil {
			panic(err)
		}
	})
}
