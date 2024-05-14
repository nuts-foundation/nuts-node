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

package storage

import (
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/test"
	"go.uber.org/goleak"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemorySessionDatabase(t *testing.T) {
	db := createDatabase(t)

	assert.NotNil(t, db)
}

func TestInMemorySessionDatabase_GetStore(t *testing.T) {
	db := createDatabase(t)

	store := db.GetStore(time.Minute, "key1", "key2").(InMemorySessionStore)

	require.NotNil(t, store)
	assert.Equal(t, time.Minute, store.ttl)
	assert.Equal(t, []string{"key1", "key2"}, store.prefixes)
}

func TestInMemorySessionStore_Put(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(InMemorySessionStore)

	t.Run("string value is stored", func(t *testing.T) {
		err := store.Put("key", "value")

		require.NoError(t, err)
		assert.Equal(t, `"value"`, store.db.entries["prefix/key"].Value)
	})

	t.Run("float value is stored", func(t *testing.T) {
		err := store.Put("key", 1.23)

		require.NoError(t, err)
		assert.Equal(t, "1.23", store.db.entries["prefix/key"].Value)
	})

	t.Run("struct value is stored", func(t *testing.T) {
		value := testStruct{
			Field1: "value",
		}

		err := store.Put("key", value)

		require.NoError(t, err)
		assert.Equal(t, "{\"field1\":\"value\"}", store.db.entries["prefix/key"].Value)
	})

	t.Run("value is not JSON", func(t *testing.T) {
		err := store.Put("key", make(chan int))

		assert.Error(t, err)
	})
}

func TestInMemorySessionStore_Get(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(InMemorySessionStore)

	t.Run("string value is retrieved correctly", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")
		var actual string

		err := store.Get(t.Name(), &actual)

		require.NoError(t, err)
		assert.Equal(t, "value", actual)
	})

	t.Run("float value is retrieved correctly", func(t *testing.T) {
		_ = store.Put(t.Name(), 1.23)
		var actual float64

		err := store.Get(t.Name(), &actual)

		require.NoError(t, err)
		assert.Equal(t, 1.23, actual)
	})

	t.Run("struct value is retrieved correctly", func(t *testing.T) {
		value := testStruct{
			Field1: "value",
		}
		_ = store.Put(t.Name(), value)
		var actual testStruct

		err := store.Get(t.Name(), &actual)

		require.NoError(t, err)
		assert.Equal(t, value, actual)
	})

	t.Run("value is not found", func(t *testing.T) {
		var actual string

		err := store.Get(t.Name(), &actual)

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("value is expired", func(t *testing.T) {
		store.db.entries["prefix/key"] = expiringEntry{
			Value:  "",
			Expiry: time.Now().Add(-time.Minute),
		}
		var actual string

		err := store.Get("key", &actual)

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("value is not JSON", func(t *testing.T) {
		store.db.entries["prefix/key"] = expiringEntry{
			Value:  "not JSON",
			Expiry: time.Now().Add(time.Minute),
		}
		var actual string

		err := store.Get("key", &actual)

		assert.Error(t, err)
	})

	t.Run("value is not a pointer", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")

		err := store.Get(t.Name(), "not a pointer")

		assert.Error(t, err)
	})
}

func TestInMemorySessionStore_Delete(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(InMemorySessionStore)

	t.Run("value is deleted", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")

		err := store.Delete(t.Name())

		require.NoError(t, err)
		_, ok := store.db.entries["prefix/key"]
		assert.False(t, ok)
	})

	t.Run("value is not found", func(t *testing.T) {
		err := store.Delete(t.Name())

		assert.NoError(t, err)
	})
}

func TestInMemorySessionStore_GetAndDelete(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(InMemorySessionStore)

	t.Run("ok", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")
		var actual string

		err := store.GetAndDelete(t.Name(), &actual)

		require.NoError(t, err)
		assert.Equal(t, "value", actual)
		// is deleted
		assert.ErrorIs(t, store.Get(t.Name(), new(string)), ErrNotFound)
	})
	t.Run("error", func(t *testing.T) {
		assert.ErrorIs(t, store.GetAndDelete(t.Name(), new(string)), ErrNotFound)
	})
}

func TestInMemorySessionDatabase_Close(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	t.Run("assert Close() waits for pruning to finish to avoid leaking goroutines", func(t *testing.T) {
		sessionStorePruneInterval = 10 * time.Millisecond
		defer func() {
			sessionStorePruneInterval = 10 * time.Minute
		}()
		store := NewInMemorySessionDatabase()
		time.Sleep(50 * time.Millisecond) // make sure pruning is running
		store.close()
	})
}

func Test_memoryStore_prune(t *testing.T) {
	t.Run("automatic", func(t *testing.T) {
		store := createDatabase(t)
		// we call startPruning a second time ourselves to speed things up, make sure not to leak the original goroutine
		defer func() {
			store.done <- struct{}{}
		}()
		store.startPruning(10 * time.Millisecond)

		err := store.GetStore(time.Millisecond).Put("key", "value")
		require.NoError(t, err)

		test.WaitFor(t, func() (bool, error) {
			store.mux.Lock()
			defer store.mux.Unlock()
			_, exists := store.entries["key"]
			return !exists, nil
		}, time.Second, "time-out waiting for entry to be pruned")
	})
	t.Run("prunes expired flows", func(t *testing.T) {
		store := createDatabase(t)
		defer store.close()

		_ = store.GetStore(0).Put("key1", "value")
		_ = store.GetStore(time.Minute).Put("key2", "value")

		count := store.prune()

		assert.Equal(t, 1, count)

		// Second round to assert there's nothing to prune now
		count = store.prune()

		assert.Equal(t, 0, count)
	})
}

type testStruct struct {
	Field1 string `json:"field1"`
}

func createDatabase(t *testing.T) *InMemorySessionDatabase {
	return NewTestInMemorySessionDatabase(t)
}
