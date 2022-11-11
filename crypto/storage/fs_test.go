/*
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

package storage

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewFileSystemBackend(t *testing.T) {
	t.Run("error - path is empty", func(t *testing.T) {
		storage, err := NewFileSystemBackend("")
		assert.EqualError(t, err, "filesystem path is empty")
		assert.Nil(t, storage)
	})
}

func Test_fs_GetPrivateKey(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))

		key, err := storage.GetPrivateKey("unknown")

		assert.Contains(t, err.Error(), "could not open entry unknown with filename")
		assert.Nil(t, key)
	})
	t.Run("private key invalid", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		kid := "kid"
		path := storage.(*fileSystemBackend).getEntryPath(kid, privateKeyEntry)
		file, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		_, err := file.WriteString("hello world")
		require.NoError(t, err)

		key, err := storage.GetPrivateKey(kid)

		assert.Nil(t, key)
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"

		err := storage.SavePrivateKey(kid, pk)
		require.NoError(t, err)

		key, err := storage.GetPrivateKey(kid)

		assert.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, pk, key)
	})
}

func Test_fs_KeyExistsFor(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		assert.False(t, storage.PrivateKeyExists("unknown"))
	})
	t.Run("existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"
		storage.SavePrivateKey(kid, pk)
		assert.True(t, storage.PrivateKeyExists(kid))
	})
}

func Test_fs_ListPrivateKeys(t *testing.T) {
	storage, _ := NewFileSystemBackend(io.TestDirectory(t))
	backend := storage.(*fileSystemBackend)

	// Generate a few keys
	pk := test.GenerateECKey()
	for i := 0; i < 5; i++ {
		kid := fmt.Sprintf("key-%d", i)
		_ = backend.SavePrivateKey(kid, pk)
	}

	// Store some other cruft that shouldn't return as private key
	_ = os.WriteFile(path.Join(backend.fspath, string(privateKeyEntry)), []byte{1, 2, 3}, os.ModePerm)
	_ = os.WriteFile(path.Join(backend.fspath, "_"+string(privateKeyEntry)), []byte{1, 2, 3}, os.ModePerm)
	_ = os.WriteFile(path.Join(backend.fspath, "foo.txt"), []byte{1, 2, 3}, os.ModePerm)
	_ = os.WriteFile(path.Join(backend.fspath, "daslkdjaslkdj_public.json"), []byte{1, 2, 3}, os.ModePerm)
	_ = os.WriteFile(path.Join(backend.fspath, "daslkdjaslkdj_private.bin"), []byte{1, 2, 3}, os.ModePerm)
	_ = os.Mkdir(path.Join(backend.fspath, "subdir"), os.ModePerm)
	_ = os.WriteFile(path.Join(backend.fspath, "subdir", "daslkdjaslkdj_public.json"), []byte{1, 2, 3}, os.ModePerm)

	keys := backend.ListPrivateKeys()
	sort.Strings(keys)
	assert.Equal(t, []string{"key-0", "key-1", "key-2", "key-3", "key-4"}, keys)
}
