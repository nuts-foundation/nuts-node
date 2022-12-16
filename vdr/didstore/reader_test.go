/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_readDocument(t *testing.T) {
	store := NewTestStore(t)

	t.Run("not found", func(t *testing.T) {
		err := store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			d, m, err := readDocumentForEvent(tx, event{DocRef: hash.RandomHash()})

			assert.Nil(t, d)
			assert.Nil(t, m)
			assert.Equal(t, types.ErrNotFound, err)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("returns embedded doc and meta when present", func(t *testing.T) {
		e := event{
			document: &did.Document{ID: testDID},
			metadata: &documentMetadata{Version: 1},
			DocRef:   hash.RandomHash(),
		}

		d, m, err := readDocumentForEvent(nil, e)

		require.Nil(t, err)
		require.NotNil(t, d)
		require.NotNil(t, m)
		assert.Equal(t, *e.document, *d)
		assert.Equal(t, *e.metadata, *m)
	})

	t.Run("data read from db", func(t *testing.T) {
		docRef := hash.RandomHash()
		metaRef := fmt.Sprintf("%s%d", testDID.String(), 0)
		document := did.Document{ID: testDID}
		metadata := documentMetadata{Version: 1}
		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			documentShelf := tx.GetShelfWriter(documentShelf)
			metadataShelf := tx.GetShelfWriter(metadataShelf)

			docBytes, _ := json.Marshal(document)
			metaBytes, _ := json.Marshal(metadata)

			_ = documentShelf.Put(stoabs.HashKey(docRef), docBytes)
			_ = metadataShelf.Put(stoabs.BytesKey(metaRef), metaBytes)

			return nil
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			d, m, err := readDocumentForEvent(tx, event{DocRef: docRef, MetaRef: metaRef})

			require.Nil(t, err)
			require.NotNil(t, d)
			require.NotNil(t, m)
			assert.Equal(t, document, *d)
			assert.Equal(t, metadata, *m)

			return nil
		})

		require.NoError(t, err)
	})
}

func Test_readEventList(t *testing.T) {
	store := NewTestStore(t)

	t.Run("empty list", func(t *testing.T) {
		err := store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			el, err := readEventList(tx, did.MustParseDID("did:nuts:unknown"))

			require.Nil(t, err)
			assert.Equal(t, 0, el.Len())

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		el := eventList{Events: []event{{DocRef: hash.RandomHash()}}}
		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			eventShelf := tx.GetShelfWriter(eventShelf)
			elBytes, _ := json.Marshal(el)
			_ = eventShelf.Put(stoabs.BytesKey(testDID.String()), elBytes)
			return nil
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			el, err := readEventList(tx, did.MustParseDID("did:nuts:unknown"))

			require.Nil(t, err)
			assert.Equal(t, 0, el.Len())

			return nil
		})
		require.NoError(t, err)
	})
}

func Test_isDuplicate(t *testing.T) {
	store := NewTestStore(t)

	t.Run("false", func(t *testing.T) {
		err := store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			dup := isDuplicate(tx, newTestTransaction(did.Document{}))

			assert.False(t, dup)

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("true", func(t *testing.T) {
		transaction := newTestTransaction(did.Document{})

		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			txShelf := tx.GetShelfWriter(transactionIndexShelf)
			_ = txShelf.Put(stoabs.HashKey(transaction.Ref), []byte{0})
			return nil
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			dup := isDuplicate(tx, transaction)

			assert.True(t, dup)

			return nil
		})
		require.NoError(t, err)
	})
}
