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
	"encoding/json"
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
			_, err := readDocument(tx, hash.SHA256Hash{})

			assert.Equal(t, types.ErrNotFound, err)

			return nil
		})
		require.NoError(t, err)
	})
}

func Test_readMetadata(t *testing.T) {
	store := NewTestStore(t)

	t.Run("not found", func(t *testing.T) {
		err := store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			_, err := readMetadata(tx, []byte{})

			assert.EqualError(t, err, "documentMetadata not found")

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
			assert.Equal(t, 0, len(el.Events))

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		el := eventList{Events: []event{{PayloadHash: hash.RandomHash()}}}
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
			assert.Equal(t, 0, len(el.Events))

			return nil
		})
		require.NoError(t, err)
	})
}
