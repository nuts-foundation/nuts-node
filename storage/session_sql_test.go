/*
 * Copyright (C) 2024 Nuts community
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
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const testKey = "keyname"

type testType struct {
	Message  string
	Audience string
}

var testValue = testType{
	Message:  "Hello!",
	Audience: "World",
}

func TestSQLSessionStore(t *testing.T) {
	storageEngine := NewTestStorageEngine(t)
	t.Run("lifecycle", func(t *testing.T) {
		sessions := NewSQLSessionDatabase(storageEngine.GetSQLDatabase())
		defer sessions.close()
		store := sessions.GetStore(time.Minute, "storename")

		var actual testType
		assert.False(t, store.Exists(testKey))
		assert.NoError(t, store.Put(testKey, testValue))
		assert.True(t, store.Exists(testKey))
		assert.NoError(t, store.Get(testKey, &actual))
		assert.Equal(t, "Hello!", actual.Message)
		assert.Equal(t, "World", actual.Audience)
		assert.NoError(t, store.Delete(testKey))
		assert.False(t, store.Exists(testKey))
	})
}

func TestSQLSessionStore_Get(t *testing.T) {
	storageEngine := NewTestStorageEngine(t)
	sessions := NewSQLSessionDatabase(storageEngine.GetSQLDatabase())
	defer sessions.close()

	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Minute, "otherstore")
	assert.NoError(t, otherStore.Put(testKey, testValue))

	var actual testType
	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Get(testKey, &actual)

		assert.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("expired entry", func(t *testing.T) {
		store := sessions.GetStore(time.Minute*-1, "storename")
		assert.NoError(t, store.Put(testKey, testValue))
		err := store.Get(testKey, &actual)

		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestSQLSessionStore_Delete(t *testing.T) {
	storageEngine := NewTestStorageEngine(t)
	sessions := NewSQLSessionDatabase(storageEngine.GetSQLDatabase())
	defer sessions.close()

	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Minute, "otherstore")
	assert.NoError(t, otherStore.Put(testKey, testValue))

	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Delete(testKey)

		assert.NoError(t, err)

		// Make sure it did not delete an entry with the same key from another store
		assert.True(t, otherStore.Exists(testKey))
	})
}

func TestSQLSessionStore_Exists(t *testing.T) {
	storageEngine := NewTestStorageEngine(t)
	sessions := NewSQLSessionDatabase(storageEngine.GetSQLDatabase())
	defer sessions.close()

	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Minute, "otherstore")
	assert.NoError(t, otherStore.Put(testKey, testValue))

	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		assert.False(t, store.Exists(testKey))
	})
	t.Run("expired entry", func(t *testing.T) {
		store := sessions.GetStore(time.Minute*-1, "storename")
		assert.NoError(t, store.Put(testKey, testValue))
		assert.False(t, store.Exists(testKey))
	})
}

func TestSQLSessionStore_Put(t *testing.T) {
	storageEngine := NewTestStorageEngine(t)
	sessions := NewSQLSessionDatabase(storageEngine.GetSQLDatabase())
	defer sessions.close()

	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Minute, "otherstore")
	assert.NoError(t, otherStore.Put(testKey, testValue))

	t.Run("overwrite", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Put(testKey, testValue)
		assert.NoError(t, err)
		err = store.Put(testKey, "new-value")
		assert.NoError(t, err)
		var actual string
		assert.NoError(t, store.Get(testKey, &actual))
		assert.Equal(t, "new-value", actual)
	})
	t.Run("Put does not overwrite other stores", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Put(testKey, "test")
		assert.NoError(t, err)

		var actual testType
		assert.NoError(t, otherStore.Get(testKey, &actual))
		assert.Equal(t, testValue, actual)
	})
}

func TestSQLSessionStore_Pruning(t *testing.T) {
	sqlSessionPruneInterval = 100 * time.Millisecond
	storageEngine := NewTestStorageEngine(t)
	db := storageEngine.GetSQLDatabase()
	sessions := NewSQLSessionDatabase(db)
	defer sessions.close()

	store := sessions.GetStore(time.Millisecond*50, "storename")
	assert.NoError(t, store.Put(testKey, testValue))
	// wait some time to make sure the pruner ran
	time.Sleep(200 * time.Millisecond)
	// don't use the store funcs, since they check for the expires property of an entry
	var count int64
	err := db.Model(&sessionStoreRecord{}).
		Where("store = ? AND key = ?", "storename", testKey).
		Count(&count).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
