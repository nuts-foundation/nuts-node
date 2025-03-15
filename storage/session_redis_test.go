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
	"errors"
	"github.com/nuts-foundation/nuts-node/json"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestRedisSessionStore(t *testing.T) {
	store, _ := NewTestStorageEngineRedis(t)
	require.NoError(t, store.Start())
	sessions := store.GetSessionDatabase()
	defer sessions.Close()

	t.Run("lifecycle", func(t *testing.T) {
		store := sessions.GetStore(time.Second, "unit")

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

func TestRedisSessionStore_Get(t *testing.T) {
	storageEngine, miniRedis := NewTestStorageEngineRedis(t)
	require.NoError(t, storageEngine.Start())
	sessions := storageEngine.GetSessionDatabase()
	defer sessions.Close()

	var actual testType
	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Get(testKey, &actual)

		assert.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("expired entry", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "otherstore")
		assert.NoError(t, store.Put(testKey, testValue))
		miniRedis.FastForward(2 * time.Minute) // cause the entry to expire

		err := store.Get(testKey, &actual)

		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestRedisSessionStore_Delete(t *testing.T) {
	store, _ := NewTestStorageEngineRedis(t)
	require.NoError(t, store.Start())
	sessions := store.GetSessionDatabase()
	defer sessions.Close()
	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Second, "unit_other")
	assert.NoError(t, otherStore.Put(testKey, testValue))

	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.Delete(testKey)

		assert.NoError(t, err)

		// Make sure it did not delete an entry with the same key from another store
		assert.True(t, otherStore.Exists(testKey))
	})
}

func TestRedisSessionStore_GetAndDelete(t *testing.T) {
	storageEngine, miniRedis := NewTestStorageEngineRedis(t)
	require.NoError(t, storageEngine.Start())
	sessions := storageEngine.GetSessionDatabase()
	defer sessions.Close()

	t.Run("ok", func(t *testing.T) {
		var actual testType

		store := sessions.GetStore(time.Minute, "storename")
		assert.NoError(t, store.Put(testKey, testValue))
		// We make sure the value exists in another store,
		// to test partitioning
		otherStore := sessions.GetStore(time.Second, "unit_other")
		assert.NoError(t, otherStore.Put(testKey, testValue))

		err := store.GetAndDelete(testKey, &actual)
		assert.NoError(t, err)
		// deleted
		assert.False(t, store.Exists(testKey))

		// Make sure it did not delete an entry with the same key from another store
		assert.True(t, otherStore.Exists(testKey))
	})
	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		err := store.GetAndDelete(testKey, new(testType))

		assert.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("expired entry", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "otherstore")
		assert.NoError(t, store.Put(testKey, testValue))
		miniRedis.FastForward(2 * time.Minute) // cause the entry to expire

		err := store.GetAndDelete(testKey, new(testType))

		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestRedisSessionStore_Exists(t *testing.T) {
	store, miniRedis := NewTestStorageEngineRedis(t)
	require.NoError(t, store.Start())
	sessions := store.GetSessionDatabase()
	defer sessions.Close()
	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Second, "unit_other")

	assert.NoError(t, otherStore.Put(testKey, testValue))

	t.Run("non-existing key", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "storename")
		assert.False(t, store.Exists(testKey))
	})

	t.Run("expired entry", func(t *testing.T) {
		store := sessions.GetStore(time.Minute, "otherstore")
		assert.NoError(t, store.Put(testKey, testValue))
		miniRedis.FastForward(2 * time.Minute) // cause the entry to expire

		assert.False(t, store.Exists(testKey))
	})
}

func TestRedisSessionStore_Put(t *testing.T) {
	store, _ := NewTestStorageEngineRedis(t)
	require.NoError(t, store.Start())
	sessions := store.GetSessionDatabase()
	defer sessions.Close()
	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Second, "unit_other")

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

func TestRedisSessionStore_Pruning(t *testing.T) {
	store, miniRedis := NewTestStorageEngineRedis(t)
	require.NoError(t, store.Start())
	sessions := store.GetSessionDatabase()
	defer sessions.Close()
	// We make sure the value exists in another store,
	// to test partitioning
	otherStore := sessions.GetStore(time.Second*1, "unit_other")

	assert.NoError(t, otherStore.Put(testKey, testValue))

	// wait some time to make sure the pruner ran
	miniRedis.FastForward(2 * time.Minute) // cause the entry to expire

	testOther := testType{}
	err := otherStore.Get(testKey, &testOther)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestRedisWithPrefixAll(t *testing.T) {
	db, mock := redismock.NewClientMock()
	sessionDatabase := NewRedisSessionDatabase(db, "one")
	store := sessionDatabase.GetStore(time.Second, "two", "three")
	expectedPrefix := "one.two.three.last"
	t.Run("test prefix all", func(t *testing.T) {
		// PUT
		marshal, _ := json.Marshal(testValue)
		mock.ExpectSet(expectedPrefix, string(marshal), time.Second).SetVal("")
		err := store.Put("last", testValue)
		assert.NoError(t, err)

		// GET
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		var actual = testType{}
		err = store.Get("last", &actual)
		assert.NoError(t, err)
		assert.Equal(t, testValue, actual)

		// EXISTS False
		mock.ExpectGet(expectedPrefix).SetVal("")
		exists := store.Exists("last")
		assert.False(t, exists)

		// EXISTS True
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		exists = store.Exists("last")
		assert.True(t, exists)

		// DELETE
		mock.ExpectDel(expectedPrefix).SetVal(0)
		err = store.Delete("last")
		assert.NoError(t, err)
	})
	t.Run("broken JSON", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).SetVal("{")
		var actual = testType{}
		err := store.Get("last", &actual)
		assert.Error(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).RedisNil()
		var actual = testType{}
		err := store.Get("last", &actual)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
	})

}
func TestRedisWithPrefixDb(t *testing.T) {
	db, mock := redismock.NewClientMock()
	sessionDatabase := NewRedisSessionDatabase(db, "one")
	store := sessionDatabase.GetStore(time.Second)
	expectedPrefix := "one.three"
	t.Run("test prefix db", func(t *testing.T) {
		// PUT
		marshal, _ := json.Marshal(testValue)
		mock.ExpectSet(expectedPrefix, string(marshal), time.Second).SetVal("")
		err := store.Put("three", testValue)
		assert.NoError(t, err)

		// GET
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		var actual = testType{}
		err = store.Get("three", &actual)
		assert.NoError(t, err)
		assert.Equal(t, testValue, actual)

		// EXISTS False
		mock.ExpectGet(expectedPrefix).SetVal("")
		exists := store.Exists("three")
		assert.False(t, exists)

		// EXISTS True
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		exists = store.Exists("three")
		assert.True(t, exists)

		// DELETE
		mock.ExpectDel(expectedPrefix).SetVal(0)
		err = store.Delete("three")
		assert.NoError(t, err)
	})
	t.Run("broken JSON", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).SetVal("{")
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).RedisNil()
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
	})
}
func TestRedisWithPrefixesClient(t *testing.T) {
	db, mock := redismock.NewClientMock()
	sessionDatabase := NewRedisSessionDatabase(db, "")
	store := sessionDatabase.GetStore(time.Second, "first", "second")
	expectedPrefix := "first.second.three"
	t.Run("test prefix db", func(t *testing.T) {
		// PUT
		marshal, _ := json.Marshal(testValue)
		mock.ExpectSet(expectedPrefix, string(marshal), time.Second).SetVal("")
		err := store.Put("three", testValue)
		assert.NoError(t, err)

		// GET
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		var actual = testType{}
		err = store.Get("three", &actual)
		assert.NoError(t, err)
		assert.Equal(t, testValue, actual)

		// EXISTS False
		mock.ExpectGet(expectedPrefix).SetVal("")
		exists := store.Exists("three")
		assert.False(t, exists)

		// EXISTS True
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		exists = store.Exists("three")
		assert.True(t, exists)

		// DELETE
		mock.ExpectDel(expectedPrefix).SetVal(0)
		err = store.Delete("three")
		assert.NoError(t, err)
	})
	t.Run("broken JSON", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).SetVal("{")
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).RedisNil()
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
	})
}

func TestRedisWithPrefixNone(t *testing.T) {
	db, mock := redismock.NewClientMock()
	sessionDatabase := NewRedisSessionDatabase(db, "")
	store := sessionDatabase.GetStore(time.Second)
	expectedPrefix := "three"
	t.Run("test prefix none", func(t *testing.T) {
		// PUT
		marshal, _ := json.Marshal(testValue)
		mock.ExpectSet(expectedPrefix, string(marshal), time.Second).SetVal("")
		err := store.Put("three", testValue)
		assert.NoError(t, err)

		// GET
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		var actual = testType{}
		err = store.Get("three", &actual)
		assert.NoError(t, err)
		assert.Equal(t, testValue, actual)

		// EXISTS False
		mock.ExpectGet(expectedPrefix).SetVal("")
		exists := store.Exists("three")
		assert.False(t, exists)

		// EXISTS True
		mock.ExpectGet(expectedPrefix).SetVal(string(marshal))
		exists = store.Exists("three")
		assert.True(t, exists)

		// DELETE
		mock.ExpectDel(expectedPrefix).SetVal(0)
		err = store.Delete("three")
		assert.NoError(t, err)
	})
	t.Run("broken JSON", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).SetVal("{")
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		mock.ExpectGet(expectedPrefix).RedisNil()
		var actual = testType{}
		err := store.Get("three", &actual)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
	})
}
