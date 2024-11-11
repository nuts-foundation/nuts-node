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
	"fmt"
	"github.com/daangn/minimemcached"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemcachedSessionDatabase(t *testing.T) {
	db := createMemcachedDatabase(t)

	assert.NotNil(t, db)
}

func TestNewMemcachedSessionDatabase_GetStore(t *testing.T) {
	db := createMemcachedDatabase(t)

	store := db.GetStore(time.Minute, "key1", "key2").(SessionStoreImpl[[]byte])

	require.NotNil(t, store)
	assert.Equal(t, time.Minute, store.ttl)
	assert.Equal(t, []string{"key1", "key2"}, store.prefixes)
}

func TestNewMemcachedSessionDatabase_Get(t *testing.T) {
	db := createMemcachedDatabase(t)
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

func TestNewMemcachedSessionDatabase_Delete(t *testing.T) {
	db := createMemcachedDatabase(t)
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

func TestNewMemcachedSessionDatabase_GetAndDelete(t *testing.T) {
	db := createMemcachedDatabase(t)
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

func getRandomAvailablePort() (int, error) {
	// Listen on a random port by specifying ":0"
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	// Extract the assigned port
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func createMemcachedDatabase(t *testing.T) *MemcachedSessionDatabase {
	// get random available port
	port, err := getRandomAvailablePort()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &minimemcached.Config{
		Port: uint16(port),
	}
	m, err := minimemcached.Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return NewMemcachedSessionDatabase(fmt.Sprintf("localhost:%d", m.Port()))
}
