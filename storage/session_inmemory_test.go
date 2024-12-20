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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemorySessionDatabase(t *testing.T) {
	db := createDatabase(t)

	assert.NotNil(t, db)
}

func TestInMemorySessionDatabase_GetStore(t *testing.T) {
	db := createDatabase(t)

	store := db.GetStore(time.Minute, "key1", "key2").(SessionStoreImpl[[]byte])

	require.NotNil(t, store)
	assert.Equal(t, time.Minute, store.ttl)
	assert.Equal(t, []string{"key1", "key2"}, store.prefixes)
}

func TestInMemorySessionStore_Exists(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix")

	t.Run("value exists", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")

		exists := store.Exists(t.Name())

		assert.True(t, exists)
	})

	t.Run("value does not exist", func(t *testing.T) {
		exists := store.Exists(t.Name())

		assert.False(t, exists)
	})
}

func TestInMemorySessionStore_Put(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix")

	t.Run("string value is stored", func(t *testing.T) {
		err := store.Put("key", "value")

		require.NoError(t, err)

		var val string
		err = store.Get("key", &val)
		require.NoError(t, err)
		assert.Equal(t, "value", val)
	})

	t.Run("float value is stored", func(t *testing.T) {
		err := store.Put("key", 1.23)

		require.NoError(t, err)

		var val float64
		err = store.Get("key", &val)
		assert.Equal(t, 1.23, val)
	})

	t.Run("struct value is stored", func(t *testing.T) {
		value := testStruct{
			Field1: "value",
		}

		err := store.Put("key", value)

		require.NoError(t, err)

		var val testStruct
		err = store.Get("key", &val)
		assert.Equal(t, value, val)
	})

	t.Run("value is not JSON", func(t *testing.T) {
		err := store.Put("key", make(chan int))

		assert.Error(t, err)
	})
}

func TestInMemorySessionStore_Get(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(SessionStoreImpl[[]byte])

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

	t.Run("value is not a pointer", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")

		err := store.Get(t.Name(), "not a pointer")

		assert.Error(t, err)
	})
}

func TestInMemorySessionStore_Delete(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(SessionStoreImpl[[]byte])

	t.Run("value is deleted", func(t *testing.T) {
		_ = store.Put(t.Name(), "value")

		err := store.Delete(t.Name())

		require.NoError(t, err)
		assert.False(t, store.Exists("prefix/key"))
	})

	t.Run("value is not found", func(t *testing.T) {
		err := store.Delete(t.Name())

		assert.NoError(t, err)
	})
}

func TestInMemorySessionStore_GetAndDelete(t *testing.T) {
	db := createDatabase(t)
	store := db.GetStore(time.Minute, "prefix").(SessionStoreImpl[[]byte])

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

type testStruct struct {
	Field1 string `json:"field1"`
}

func createDatabase(t *testing.T) *InMemorySessionDatabase {
	return NewTestInMemorySessionDatabase(t)
}
