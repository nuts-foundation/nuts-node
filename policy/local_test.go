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

func TestLocalPDP_FindCredentialProfile(t *testing.T) {
	t.Run("err - not found", func(t *testing.T) {
		store := LocalPDP{}

		_, err := store.FindCredentialProfile(context.Background(), "unknown-scope")

		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("returns match for existing scope", func(t *testing.T) {
		store := LocalPDP{}
		err := store.loadFromFile("test/definition_mapping.json")
		require.NoError(t, err)

		match, err := store.FindCredentialProfile(context.Background(), "example-scope")

		require.NoError(t, err)
		assert.Equal(t, "example-scope", match.CredentialProfileScope)
		assert.NotNil(t, match.WalletOwnerMapping)
		assert.Equal(t, ScopePolicyProfileOnly, match.ScopePolicy)
		assert.Empty(t, match.OtherScopes)
	})
	t.Run("multi-scope with one profile scope returns match and other scopes", func(t *testing.T) {
		store := LocalPDP{}
		err := store.loadFromFile("test/definition_mapping.json")
		require.NoError(t, err)

		match, err := store.FindCredentialProfile(context.Background(), "example-scope patient/Observation.read launch/patient")

		require.NoError(t, err)
		assert.Equal(t, "example-scope", match.CredentialProfileScope)
		assert.NotNil(t, match.WalletOwnerMapping)
		assert.Equal(t, []string{"patient/Observation.read", "launch/patient"}, match.OtherScopes)
	})
	t.Run("err - multiple credential profile scopes", func(t *testing.T) {
		store := LocalPDP{}
		err := store.loadFromDirectory("test/2_files")
		require.NoError(t, err)

		_, err = store.FindCredentialProfile(context.Background(), "1 2")

		assert.ErrorIs(t, err, ErrNotFound)
		assert.ErrorContains(t, err, "multiple credential profile scopes")
	})
	t.Run("err - no credential profile scope", func(t *testing.T) {
		store := LocalPDP{}
		err := store.loadFromFile("test/definition_mapping.json")
		require.NoError(t, err)

		_, err = store.FindCredentialProfile(context.Background(), "unknown-a unknown-b")

		assert.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("err - empty scope string", func(t *testing.T) {
		store := LocalPDP{}

		_, err := store.FindCredentialProfile(context.Background(), "")

		assert.ErrorIs(t, err, ErrNotFound)
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

		match, err := store.FindCredentialProfile(context.Background(), "example-scope")
		require.NoError(t, err)
		assert.Equal(t, "example-scope", match.CredentialProfileScope)
	})
	t.Run("2 files, 3 scopes", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test/2_files")
		require.NoError(t, err)

		_, err = store.FindCredentialProfile(context.Background(), "1")
		require.NoError(t, err)
		_, err = store.FindCredentialProfile(context.Background(), "2")
		require.NoError(t, err)
		_, err = store.FindCredentialProfile(context.Background(), "3")
		require.NoError(t, err)
	})
	t.Run("2 files, duplicate scope", func(t *testing.T) {
		store := LocalPDP{}

		err := store.loadFromDirectory("test/2_files_duplicate")

		require.EqualError(t, err, "mapping for scope '1' already exists (file=test/2_files_duplicate/2.json)")
	})
}
