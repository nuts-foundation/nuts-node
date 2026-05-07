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

package issuer

import (
	"context"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"testing"
)

const refType = "ref-type"
const ref = "ref-value"

func Test_memoryStore_DeleteReference(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID: "flow-id",
		}
		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		err = store.StoreReference(context.Background(), expected.ID, refType, ref)
		assert.NoError(t, err)

		err = store.DeleteReference(context.Background(), refType, ref)
		assert.NoError(t, err)

		// Now it can't be found anymore
		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("unknown reference", func(t *testing.T) {
		store := createStore(t)

		err := store.DeleteReference(context.Background(), refType, ref)

		assert.NoError(t, err)
	})
}

func Test_memoryStore_FindByReference(t *testing.T) {
	t.Run("reference already exists", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID: "flow-id",
		}
		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)

		err = store.StoreReference(context.Background(), expected.ID, refType, ref)
		assert.NoError(t, err)
		err = store.StoreReference(context.Background(), expected.ID, refType, ref)

		assert.EqualError(t, err, "reference already exists")
	})
	t.Run("invalid reference", func(t *testing.T) {
		store := createStore(t)

		err := store.StoreReference(context.Background(), "unknown", refType, "")

		assert.EqualError(t, err, "invalid reference")
	})
	t.Run("unknown flow", func(t *testing.T) {
		store := createStore(t)

		err := store.StoreReference(context.Background(), "unknown", refType, ref)

		assert.EqualError(t, err, "OAuth2 flow with this ID does not exist")
	})
}

func Test_memoryStore_Store(t *testing.T) {
	ctx := context.Background()
	t.Run("write, then read", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID: "flow-id",
		}

		err := store.Store(ctx, expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(ctx, expected.ID, refType, ref)
		assert.NoError(t, err)

		actual, err := store.FindByReference(ctx, refType, ref)
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("already exists", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID: "flow-id",
		}

		err := store.Store(ctx, expected)
		assert.NoError(t, err)
		err = store.Store(ctx, expected)

		assert.EqualError(t, err, "OAuth2 flow with this ID already exists")
	})
}

func createStore(t *testing.T) *openidMemoryStore {
	storageDatabase := storage.NewTestInMemorySessionDatabase(t)
	store := NewOpenIDMemoryStore(storageDatabase).(*openidMemoryStore)
	return store
}
