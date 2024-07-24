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

package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_LoadFromFile(t *testing.T) {
	t.Run("loads the mapping from the file", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromFile("test/definition_mapping.json")

		require.NoError(t, err)
		assert.Len(t, store.mapping, 1)
		assert.NotNil(t, store.mapping["example-scope"])
	})

	t.Run("returns an error if the file doesn't exist", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromFile("test/doesntexist.json")

		assert.Error(t, err)
	})

	t.Run("returns an error if a presentation definition is invalid", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromFile("test/invalid/invalid_definition_mapping.json")

		assert.ErrorContains(t, err, "missing properties: \"input_descriptors\"")
	})
}

func TestStore_PresentationDefinitions(t *testing.T) {
	t.Run("err - not found", func(t *testing.T) {
		store := LocalPDP{}

		_, err := store.PresentationDefinitions(context.Background(), "example-scope2")

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("returns the presentation definition if the scope exists", func(t *testing.T) {
		store := LocalPDP{}
		err := store.loadFromFile("test/definition_mapping.json")
		require.NoError(t, err)

		result, err := store.PresentationDefinitions(context.Background(), "example-scope")

		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func Test_LocalPDP_loadFromDirectory(t *testing.T) {
	t.Run("no files", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test/no_files")
		require.NoError(t, err)
	})
	t.Run("1 file", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test")
		require.NoError(t, err)

		_, err = store.PresentationDefinitions(context.Background(), "example-scope")
		require.NoError(t, err)
	})
	t.Run("2 files, 3 scopes", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test/2_files")
		require.NoError(t, err)

		_, err = store.PresentationDefinitions(context.Background(), "1")
		require.NoError(t, err)
		_, err = store.PresentationDefinitions(context.Background(), "2")
		require.NoError(t, err)
		_, err = store.PresentationDefinitions(context.Background(), "3")
		require.NoError(t, err)
	})
	t.Run("2 files, duplicate scope", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test/2_files_duplicate")

		require.EqualError(t, err, "mapping for scope '1' already exists (file=test/2_files_duplicate/2.json)")
	})
}
