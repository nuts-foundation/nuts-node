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

package store

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
	"github.com/nuts-foundation/nuts-node/vdr/types"
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

		assert.ErrorIs(t, err, types.ErrNotFound)
	})

	t.Run("latest", func(t *testing.T) {
		doc, meta, err := store.Resolve(testDID, nil)

		require.NoError(t, err)
		assert.Len(t, doc.Service, 1)
		assert.NotNil(t, meta.PreviousHash)
	})

	t.Run("previous", func(t *testing.T) {
		before := txUpdate.SigningTime.Add(-1 * time.Second)
		doc, meta, err := store.Resolve(testDID, &types.ResolveMetadata{ResolveTime: &before})

		require.NoError(t, err)
		assert.Len(t, doc.Service, 0)
		assert.Nil(t, meta.PreviousHash)
	})

	t.Run("to far back", func(t *testing.T) {
		before := txUpdate.SigningTime.Add(-3 * time.Second)
		_, _, err := store.Resolve(testDID, &types.ResolveMetadata{ResolveTime: &before})

		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("deactivated", func(t *testing.T) {
		store := NewTestStore(t)
		update := did.Document{ID: testDID}
		txUpdate := newTestTransaction(update, txCreate.Ref)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		_, _, err := store.Resolve(testDID, nil)

		assert.Equal(t, types.ErrDeactivated, err)
	})

	t.Run("deactivated, but specifically asking for !allowDeactivated", func(t *testing.T) {
		store := NewTestStore(t)
		update := did.Document{ID: testDID}
		txUpdate := newTestTransaction(update, txCreate.Ref)
		add(t, store, create, txCreate)
		add(t, store, update, txUpdate)

		_, _, err := store.Resolve(testDID, &types.ResolveMetadata{})

		assert.Equal(t, types.ErrDeactivated, err)
	})
}

func TestStore_Iterate(t *testing.T) {
	store := NewTestStore(t)

	document := did.Document{ID: testDID}
	transaction := newTestTransaction(document)
	add(t, store, document, transaction)

	err := store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
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

			assert.True(t, matches(metadata, &types.ResolveMetadata{ResolveTime: &resolveTime}))
		})
		t.Run("no resolveMetadata", func(t *testing.T) {
			assert.True(t, matches(metadata, nil))
		})
		t.Run("empty resolveMetadata", func(t *testing.T) {
			assert.True(t, matches(metadata, &types.ResolveMetadata{}))
		})
		t.Run("deactivated", func(t *testing.T) {
			assert.True(t, matches(deactivated, &types.ResolveMetadata{AllowDeactivated: true}))
		})
		t.Run("source transaction", func(t *testing.T) {
			assert.True(t, matches(metadata, &types.ResolveMetadata{SourceTransaction: &h}))
		})
		t.Run("hash", func(t *testing.T) {
			assert.True(t, matches(metadata, &types.ResolveMetadata{Hash: &h}))
		})
	})
	t.Run("false", func(t *testing.T) {
		t.Run("time", func(t *testing.T) {
			resolveTime := now.Add(-3 * time.Second)

			assert.False(t, matches(metadata, &types.ResolveMetadata{ResolveTime: &resolveTime}))
		})
		t.Run("no meta and deactivated", func(t *testing.T) {
			assert.False(t, matches(deactivated, nil))
		})
		t.Run("hash", func(t *testing.T) {
			assert.False(t, matches(metadata, &types.ResolveMetadata{Hash: &h2}))
		})
		t.Run("source transaction", func(t *testing.T) {
			assert.False(t, matches(metadata, &types.ResolveMetadata{SourceTransaction: &h2}))
		})
	})
}
