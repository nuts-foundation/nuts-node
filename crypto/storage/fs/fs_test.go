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

package fs

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewFileSystemBackend(t *testing.T) {
	t.Run("error - path is empty", func(t *testing.T) {
		storage, err := NewFileSystemBackend("")
		assert.EqualError(t, err, "filesystem path is empty")
		assert.Nil(t, storage)
	})
	t.Run("error - path is a file", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "")
		require.NoError(t, err)
		_ = tempFile.Close()
		storage, err := NewFileSystemBackend(tempFile.Name())
		assert.ErrorIs(t, err, syscall.ENOTDIR)
		assert.Nil(t, storage)
	})
	t.Run("it creates the dir with the right permissions", func(t *testing.T) {
		tmpDirPath := t.TempDir()
		keysDirPath := filepath.Join(tmpDirPath, "keys")

		_, err := NewFileSystemBackend(keysDirPath)
		require.NoError(t, err)

		fileInfo, err := os.Stat(keysDirPath)
		require.NoError(t, err)
		assert.Equal(t, fileInfo.IsDir(), true)
		assert.Equal(t, fs.FileMode(0700), fileInfo.Mode().Perm())
	})
}

func TestFileSystemBackend_SavePrivateKey(t *testing.T) {
	pk := test.GenerateECKey()
	kid := "kid"

	t.Run("it fails when the file already exists", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		storage, _ := NewFileSystemBackend(testDir)

		filename := filepath.Join(testDir, getEntryFileName(kid, privateKeyEntry))
		_, err := os.Create(filename)
		require.NoError(t, err)

		err = storage.SavePrivateKey(nil, kid, pk)
		assert.ErrorContains(t, err, "file exists")
	})

	t.Run("is creates with the right file permissions", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		storage, _ := NewFileSystemBackend(testDir)

		err := storage.SavePrivateKey(nil, kid, pk)
		require.NoError(t, err)

		// Check the file permissions:
		filename := filepath.Join(testDir, getEntryFileName(kid, privateKeyEntry))
		info, err := os.Stat(filename)
		require.NoError(t, err)

		assert.Equal(t, fs.FileMode(0600), info.Mode().Perm())
	})
}

func Test_fileSystemBackend_DeletePrivateKey(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))

		err := storage.DeletePrivateKey(nil, "unknown")

		assert.ErrorIs(t, err, spi.ErrNotFound)
	})
	t.Run("ok", func(t *testing.T) {
		pk := test.GenerateECKey()
		kid := "kid"
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		_ = storage.SavePrivateKey(nil, kid, pk)

		err := storage.DeletePrivateKey(nil, kid)

		assert.NoError(t, err)
	})
}

func Test_fs_GetPrivateKey(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))

		key, err := storage.GetPrivateKey(nil, "unknown")

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

		key, err := storage.GetPrivateKey(nil, kid)

		assert.Nil(t, key)
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"

		err := storage.SavePrivateKey(nil, kid, pk)
		require.NoError(t, err)

		key, err := storage.GetPrivateKey(nil, kid)

		assert.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, pk, key)
	})
}

func Test_fs_KeyExistsFor(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		assert.False(t, storage.PrivateKeyExists(nil, "unknown"))
	})
	t.Run("existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"
		storage.SavePrivateKey(nil, kid, pk)
		assert.True(t, storage.PrivateKeyExists(nil, kid))
	})
}

func Test_fs_ListPrivateKeys(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		backend := storage.(*fileSystemBackend)

		// Generate a few keys
		pk := test.GenerateECKey()
		for i := 0; i < 5; i++ {
			kid := fmt.Sprintf("key-%d", i)
			_ = backend.SavePrivateKey(nil, kid, pk)
		}

		// Store some other cruft that shouldn't return as private key
		_ = os.WriteFile(path.Join(backend.fspath, string(privateKeyEntry)), []byte{1, 2, 3}, os.ModePerm)
		_ = os.WriteFile(path.Join(backend.fspath, "_"+string(privateKeyEntry)), []byte{1, 2, 3}, os.ModePerm)
		_ = os.WriteFile(path.Join(backend.fspath, "foo.txt"), []byte{1, 2, 3}, os.ModePerm)
		_ = os.WriteFile(path.Join(backend.fspath, "daslkdjaslkdj_public.json"), []byte{1, 2, 3}, os.ModePerm)
		_ = os.WriteFile(path.Join(backend.fspath, "daslkdjaslkdj_private.bin"), []byte{1, 2, 3}, os.ModePerm)
		_ = os.Mkdir(path.Join(backend.fspath, "subdir"), os.ModePerm)
		_ = os.WriteFile(path.Join(backend.fspath, "subdir", "daslkdjaslkdj_public.json"), []byte{1, 2, 3}, os.ModePerm)

		keys := backend.ListPrivateKeys(nil)
		sort.Strings(keys)
		assert.Equal(t, []string{"key-0", "key-1", "key-2", "key-3", "key-4"}, keys)
	})
	t.Run("WalkFunc error", func(t *testing.T) {
		// https://github.com/nuts-foundation/nuts-node/issues/1943
		// ListPrivateKeys uses path.WalkFunc, which gets called with a non-nil error in case Lstat fails.
		// This happens when the root directory does not exist (or any other underlying FS error).
		storage := &fileSystemBackend{fspath: path.Join(io.TestDirectory(t), "does-not-exist")}

		keys := storage.ListPrivateKeys(nil)

		assert.Empty(t, keys)
	})
}
