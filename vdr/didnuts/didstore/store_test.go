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
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/redis7"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStore_Add(t *testing.T) {
	create := did.Document{ID: testDID, Controller: []did.DID{testDID}}
	txCreate := newTestTransaction(create)
	update := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{{ID: ssi.MustParseURI("service")}}}
	txUpdate := newTestTransaction(update, txCreate.Ref)
	txUpdate.SigningTime = txCreate.SigningTime
	txCreate.SigningTime = txCreate.SigningTime.Add(-2 * time.Second)

	t.Run("create ok", func(t *testing.T) {
		store := NewTestStore(t)

		require.NoError(t, store.Add(create, txCreate))

		t.Run("metadata ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
				metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s0", testDID.String())))
				if err != nil {
					return err
				}
				metadata := documentMetadata{}
				err = json.Unmarshal(metaBytes, &metadata)
				if err != nil {
					return err
				}

				assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
				assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Updated.Unix())
				assert.Nil(t, metadata.PreviousHash)
				assert.Equal(t, txCreate.PayloadHash, metadata.Hash)
				assert.Nil(t, metadata.PreviousTransaction)
				assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.SourceTransactions)
				assert.Equal(t, 0, metadata.Version)
				assert.Equal(t, false, metadata.Deactivated)

				return nil
			})
			require.NoError(t, err)
		})

		t.Run("document ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), documentShelf, func(reader stoabs.Reader) error {
				bytes, err := reader.Get(stoabs.HashKey(txCreate.PayloadHash))
				if err != nil {
					return err
				}
				document := did.Document{}
				err = json.Unmarshal(bytes, &document)
				if err != nil {
					return err
				}

				assert.Equal(t, create, document)

				return nil
			})
			require.NoError(t, err)
		})

		t.Run("latest ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), latestShelf, func(reader stoabs.Reader) error {
				bytes, err := reader.Get(stoabs.BytesKey(testDID.String()))
				if err != nil {
					return err
				}
				assert.Equal(t, fmt.Sprintf("%s0", testDID.String()), string(bytes))

				return nil
			})
			require.NoError(t, err)
		})
	})

	t.Run("duplicate ok", func(t *testing.T) {
		store := NewTestStore(t)

		require.NoError(t, store.Add(create, txCreate))
		require.NoError(t, store.Add(create, txCreate))

		err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
			metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s0", testDID.String())))
			if err != nil {
				return err
			}
			metadata := documentMetadata{}
			err = json.Unmarshal(metaBytes, &metadata)
			if err != nil {
				return err
			}

			assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
			assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Updated.Unix())
			assert.Nil(t, metadata.PreviousHash)
			assert.Equal(t, txCreate.PayloadHash, metadata.Hash)
			assert.Nil(t, metadata.PreviousTransaction)
			assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.SourceTransactions)
			assert.Equal(t, 0, metadata.Version)
			assert.Equal(t, false, metadata.Deactivated)

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("update ok", func(t *testing.T) {
		store := NewTestStore(t)

		require.NoError(t, store.Add(update, txUpdate))
		require.NoError(t, store.Add(create, txCreate))

		t.Run("metadata ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
				metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s1", testDID.String())))
				if err != nil {
					return err
				}
				metadata := documentMetadata{}
				err = json.Unmarshal(metaBytes, &metadata)
				if err != nil {
					return err
				}

				assert.Equal(t, txCreate.SigningTime.Unix(), metadata.Created.Unix())
				assert.Equal(t, txUpdate.SigningTime.Unix(), metadata.Updated.Unix())
				require.NotNil(t, metadata.PreviousHash)
				assert.Equal(t, txCreate.PayloadHash, *metadata.PreviousHash)
				assert.Equal(t, txUpdate.PayloadHash, metadata.Hash)
				assert.Equal(t, []hash.SHA256Hash{txCreate.Ref}, metadata.PreviousTransaction)
				assert.Equal(t, []hash.SHA256Hash{txUpdate.Ref}, metadata.SourceTransactions)
				assert.Equal(t, 1, metadata.Version)
				assert.Equal(t, false, metadata.Deactivated)

				return nil
			})
			require.NoError(t, err)
		})

		t.Run("document ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), documentShelf, func(reader stoabs.Reader) error {
				bytes, err := reader.Get(stoabs.HashKey(txCreate.PayloadHash))
				if err != nil {
					return err
				}
				document := did.Document{}
				err = json.Unmarshal(bytes, &document)
				if err != nil {
					return err
				}

				assert.Equal(t, create, document)

				return nil
			})
			require.NoError(t, err)
		})

		t.Run("latest ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), latestShelf, func(reader stoabs.Reader) error {
				bytes, err := reader.Get(stoabs.BytesKey(testDID.String()))
				if err != nil {
					return err
				}
				assert.Equal(t, fmt.Sprintf("%s1", testDID.String()), string(bytes))

				return nil
			})
			require.NoError(t, err)
		})
	})

	t.Run("once deactivated is always deactivated", func(t *testing.T) {
		store := NewTestStore(t)

		deactivate := create
		deactivate.Controller = nil
		deactivate.VerificationMethod = nil
		txDeactivate := newTestTransaction(deactivate, txCreate.Ref)
		update := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{{ID: ssi.MustParseURI("service")}}}
		txUpdate := newTestTransaction(update, txDeactivate.Ref)

		require.NoError(t, store.Add(create, txCreate))
		require.NoError(t, store.Add(deactivate, txDeactivate))
		require.NoError(t, store.Add(update, txUpdate))

		t.Run("metadata ok", func(t *testing.T) {
			err := store.db.ReadShelf(context.Background(), metadataShelf, func(reader stoabs.Reader) error {
				for i := range []int{0, 1, 2} {
					metaBytes, err := reader.Get(stoabs.BytesKey(fmt.Sprintf("%s%d", testDID.String(), i)))
					if err != nil {
						return err
					}
					metadata := documentMetadata{}
					err = json.Unmarshal(metaBytes, &metadata)
					if err != nil {
						return err
					}
					assert.Equal(t, i > 0, metadata.Deactivated, "document version %d", i)
				}
				return nil
			})
			require.NoError(t, err)
		})

	})
}

func TestStore_Resolve(t *testing.T) {
	store := NewTestStore(t)
	create := did.Document{ID: testDID, Controller: []did.DID{testDID}}
	txCreate := newTestTransaction(create)
	update := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{{ID: ssi.MustParseURI("service")}}}
	txUpdate := newTestTransaction(update)
	txUpdate.SigningTime = txCreate.SigningTime
	txCreate.SigningTime = txCreate.SigningTime.Add(-2 * time.Second)
	add(t, store, create, txCreate)
	add(t, store, update, txUpdate)

	t.Run("not found", func(t *testing.T) {
		_, _, err := store.Resolve(did.MustParseDID("did:nuts:unknown"), nil)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
	})

	t.Run("latest", func(t *testing.T) {
		doc, meta, err := store.Resolve(testDID, nil)

		require.NoError(t, err)
		assert.Len(t, doc.Service, 1)
		assert.NotNil(t, meta.PreviousHash)
	})

	t.Run("previous", func(t *testing.T) {
		before := txUpdate.SigningTime.Add(-1 * time.Second)
		doc, meta, err := store.Resolve(testDID, &resolver.ResolveMetadata{ResolveTime: &before})

		require.NoError(t, err)
		assert.Len(t, doc.Service, 0)
		assert.Nil(t, meta.PreviousHash)
	})

	t.Run("to far back", func(t *testing.T) {
		before := txUpdate.SigningTime.Add(-3 * time.Second)
		_, _, err := store.Resolve(testDID, &resolver.ResolveMetadata{ResolveTime: &before})

		assert.Equal(t, resolver.ErrNotFound, err)
	})

	t.Run("deactivated", func(t *testing.T) {
		store := NewTestStore(t)
		update := did.Document{ID: testDID}
		txUpdate := newTestTransaction(update, txCreate.Ref)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		_, _, err := store.Resolve(testDID, nil)

		assert.Equal(t, resolver.ErrDeactivated, err)
	})

	t.Run("deactivated, but specifically asking for !allowDeactivated", func(t *testing.T) {
		store := NewTestStore(t)
		update := did.Document{ID: testDID}
		txUpdate := newTestTransaction(update, txCreate.Ref)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		_, _, err := store.Resolve(testDID, &resolver.ResolveMetadata{})

		assert.Equal(t, resolver.ErrDeactivated, err)
	})
}

func TestStore_Iterate(t *testing.T) {
	store := NewTestStore(t)

	document := did.Document{ID: testDID}
	transaction := newTestTransaction(document)
	add(t, store, document, transaction)

	err := store.Iterate(func(doc did.Document, metadata resolver.DocumentMetadata) error {
		assert.Equal(t, document, doc)
		assert.Equal(t, []hash.SHA256Hash{transaction.Ref}, metadata.SourceTransactions)
		return nil
	})
	require.NoError(t, err)
}

func TestStore_ConflictedCount(t *testing.T) {
	store := NewTestStore(t)
	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	doc2 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	tx1 := newTestTransaction(doc1)
	tx2 := newTestTransaction(doc2)
	add(t, store, doc1, tx1)
	add(t, store, doc2, tx2)

	t.Run("stats are written", func(t *testing.T) {
		err := store.db.ReadShelf(context.Background(), statsShelf, func(reader stoabs.Reader) error {
			cBytes, _ := reader.Get(stoabs.BytesKey(conflictedCountKey))
			require.True(t, len(cBytes) > 0)
			assert.Equal(t, uint32(1), binary.BigEndian.Uint32(cBytes))

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("conflictedShelf is written", func(t *testing.T) {
		count := 0
		err := store.db.ReadShelf(context.Background(), conflictedShelf, func(reader stoabs.Reader) error {
			return reader.Iterate(func(key stoabs.Key, value []byte) error {
				count++
				assert.Equal(t, testDID.String(), string(key.Bytes()))

				return nil
			}, stoabs.BytesKey{})
		})
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})
}

func TestStore_DocumentCount(t *testing.T) {
	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	tx1 := newTestTransaction(doc1)

	t.Run("ok for 0", func(t *testing.T) {
		store := NewTestStore(t)

		count, err := store.DocumentCount()

		require.NoError(t, err)
		assert.Equal(t, uint(0), count)
	})

	t.Run("ok for > 0", func(t *testing.T) {
		store := NewTestStore(t)
		add(t, store, doc1, tx1)

		count, err := store.DocumentCount()

		require.NoError(t, err)
		assert.Equal(t, uint(1), count)
	})
}

func TestStore_Redis(t *testing.T) {
	// This test uses github.com/alicebob/miniredis/v2
	// A separate test for redis is required, because redis does not have transaction isolation
	// go-stoabs writes all changes to redis on commit, any read during the transaction will read old/stale data.
	redisServer := miniredis.RunT(t)
	redisClient, err := redis7.CreateRedisStore("db", &redis.Options{
		Addr: redisServer.Addr(),
	})
	require.NoError(t, err)
	store := New(nil).(*store)
	store.db = redisClient
	create := did.Document{ID: testDID, Controller: []did.DID{testDID}}
	txCreate := newTestTransaction(create)

	err = store.Add(create, txCreate)

	assert.NoError(t, err)
}

func Test_matches(t *testing.T) {
	now := time.Now()
	h := hash.RandomHash()
	h2 := hash.RandomHash()
	metadata := documentMetadata{
		Created:            now.Add(-4 * time.Second),
		Updated:            now.Add(-2 * time.Second),
		Hash:               h,
		SourceTransactions: []hash.SHA256Hash{h},
		Deactivated:        false,
	}
	deactivated := metadata
	deactivated.Deactivated = true

	t.Run("true", func(t *testing.T) {
		t.Run("time", func(t *testing.T) {
			resolveTime := now.Add(-1 * time.Second)

			assert.True(t, matches(metadata, &resolver.ResolveMetadata{ResolveTime: &resolveTime}))
		})
		t.Run("no resolveMetadata", func(t *testing.T) {
			assert.True(t, matches(metadata, nil))
		})
		t.Run("empty resolveMetadata", func(t *testing.T) {
			assert.True(t, matches(metadata, &resolver.ResolveMetadata{}))
		})
		t.Run("deactivated", func(t *testing.T) {
			assert.True(t, matches(deactivated, &resolver.ResolveMetadata{AllowDeactivated: true}))
		})
		t.Run("source transaction", func(t *testing.T) {
			assert.True(t, matches(metadata, &resolver.ResolveMetadata{SourceTransaction: &h}))
		})
		t.Run("hash", func(t *testing.T) {
			assert.True(t, matches(metadata, &resolver.ResolveMetadata{Hash: &h}))
		})
	})
	t.Run("false", func(t *testing.T) {
		t.Run("time", func(t *testing.T) {
			resolveTime := now.Add(-3 * time.Second)

			assert.False(t, matches(metadata, &resolver.ResolveMetadata{ResolveTime: &resolveTime}))
		})
		t.Run("no meta and deactivated", func(t *testing.T) {
			assert.False(t, matches(deactivated, nil))
		})
		t.Run("hash", func(t *testing.T) {
			assert.False(t, matches(metadata, &resolver.ResolveMetadata{Hash: &h2}))
		})
		t.Run("source transaction", func(t *testing.T) {
			assert.False(t, matches(metadata, &resolver.ResolveMetadata{SourceTransaction: &h2}))
		})
	})
}

func TestStore_HistorySinceVersion(t *testing.T) {
	store := NewTestStore(t)

	// create DID document with some updates and a document conflict
	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA}}
	tx1 := newTestTransaction(doc1) // serviceA
	tx1.SigningTime = time.Now().Add(-time.Second)
	doc2a := did.Document{ID: testDID, Service: []did.Service{testServiceA}}
	tx2a := newTestTransaction(doc2a, tx1.Ref) // deactivate
	doc2b := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceB}}
	tx2b := newTestTransaction(doc2b, tx1.Ref) // serviceB
	doc3 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{testServiceA, testServiceB}}
	tx3 := newTestTransaction(doc3, tx2a.Ref, tx2b.Ref) // serviceA + serviceB

	// add all transactions.
	// txs all have LC=0, so they are sorted on SigningTime. Nano-sec timestamps guarantee that the tx{1,2a,2b,3} order is preserved
	require.NoError(t, store.Add(doc1, tx1))
	require.NoError(t, store.Add(doc2a, tx2a))
	require.NoError(t, store.Add(doc2b, tx2b))
	require.NoError(t, store.Add(doc3, tx3))

	// raw documents in order
	raw := [4][]byte{}
	raw[0], _ = json.Marshal(doc1)
	raw[1], _ = json.Marshal(doc2a)
	raw[2], _ = json.Marshal(doc2b)
	raw[3], _ = json.Marshal(doc3)

	t.Run("ok - full history", func(t *testing.T) {
		history, err := store.HistorySinceVersion(testDID, 0)
		assert.NoError(t, err)
		require.Len(t, history, 4)

		for idx, tx := range []Transaction{tx1, tx2a, tx2b, tx3} {
			result := history[idx]
			assert.Equal(t, raw[idx], result.Raw) // make sure result.Raw contains the original documents, not the merged document conflicts
			assert.True(t, tx1.SigningTime.Equal(result.Created))
			assert.True(t, tx.SigningTime.Equal(result.Updated))
			assert.Equal(t, idx, result.Version)
		}
	})
	t.Run("ok - partial history", func(t *testing.T) {
		history, err := store.HistorySinceVersion(testDID, 1)
		assert.NoError(t, err)
		require.Len(t, history, 3)
		assert.Equal(t, 1, history[0].Version)
	})
	t.Run("ok - no version updates", func(t *testing.T) {
		history, err := store.HistorySinceVersion(testDID, 5)
		assert.NoError(t, err)
		assert.Len(t, history, 0)
	})
	t.Run("error - negative version", func(t *testing.T) {
		history, err := store.HistorySinceVersion(testDID, -1)
		assert.EqualError(t, err, "negative version")
		assert.Nil(t, history)
	})
	t.Run("error - unknown DID", func(t *testing.T) {
		history, err := store.HistorySinceVersion(did.MustParseDID("did:nuts:unknown"), 0)
		assert.ErrorIs(t, err, storage.ErrNotFound)
		assert.Nil(t, history)
	})
	t.Run("error - document version not found", func(t *testing.T) {
		err := store.db.WriteShelf(context.Background(), documentShelf, func(writer stoabs.Writer) error {
			return writer.Delete(stoabs.NewHashKey(tx1.PayloadHash))
		})
		require.NoError(t, err)

		history, err := store.HistorySinceVersion(testDID, 0)
		assert.ErrorIs(t, err, storage.ErrNotFound)
		assert.Nil(t, history)
	})
}

//func Test_DIDMigration(t *testing.T) {
//	// the eventShelf points to all payloads as received through the network
//	// the documentShelf contains all documents as payload:raw-bytes, however, the raw-bytes are reproductions of the original payload by un/marshalling the data
//	// this test loops over the data to confirm the hash of the data on the documentShelf is the same as the original payloadHash.
//	// if true, we can safely use this data and do not have to extract the data from the network/data.db. (scoping of stores to modules + bbolt means it is easier to use the vdr/didstore.db)
//
//	db, err := storage.NewTestStorageEngineInDir(t, "../../..").GetProvider("migration_test").GetKVStore("prd_didstore", storage.PersistentStorageClass)
//	require.NoError(t, err)
//	unequals := 0
//	txErr := db.Read(context.TODO(), func(tx stoabs.ReadTx) error {
//		documentReader := tx.GetShelfReader(documentShelf)
//		return tx.GetShelfReader(eventShelf).Iterate(func(key stoabs.Key, value []byte) error {
//			fmt.Println(did.MustParseDID(string(key.Bytes())))
//			el := eventList{}
//			err = json.Unmarshal(value, &el)
//			if err != nil {
//				return fmt.Errorf("unmarshal error on eventList: %w", err)
//			}
//
//			for v := range el.Events {
//				payloadHash := el.Events[v].PayloadHash
//				documentBytes, err := documentReader.Get(stoabs.NewHashKey(payloadHash))
//				if err != nil {
//					if errors.Is(err, stoabs.ErrKeyNotFound) {
//						return storage.ErrNotFound
//					}
//					return err
//				}
//				equal := payloadHash.Equals(hash.SHA256Sum(documentBytes))
//				fmt.Printf("\tdocument version: %d; equal: %v\n", v, equal)
//				if !equal {
//					unequals++
//				}
//			}
//
//			return nil
//		}, stoabs.BytesKey("hello"))
//	})
//	if txErr != nil {
//		fmt.Printf("failed: %s\n", txErr)
//	}
//	fmt.Printf("Number of unequals: %d\n", unequals)
//}
