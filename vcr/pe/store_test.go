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

package pe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_LoadFromFile(t *testing.T) {
	t.Run("loads the mapping from the file", func(t *testing.T) {
		store := Store{}

		err := store.LoadFromFile("test/definition_mapping.json")

		require.NoError(t, err)
		assert.Len(t, store.mapping, 1)
		assert.NotNil(t, store.mapping["eOverdracht-overdrachtsbericht"])
	})

	t.Run("returns an error if the file doesn't exist", func(t *testing.T) {
		store := Store{}

		err := store.LoadFromFile("test/doesntexist.json")

		assert.Error(t, err)
	})
}

func TestStore_ByScope(t *testing.T) {
	t.Run("returns nil if the scope doesn't exist", func(t *testing.T) {
		store := Store{}

		result := store.ByScope("eOverdracht-overdrachtsbericht2")

		assert.Nil(t, result)
	})

	t.Run("returns the presentation definition if the scope exists", func(t *testing.T) {
		store := Store{}
		err := store.LoadFromFile("test/definition_mapping.json")
		require.NoError(t, err)

		result := store.ByScope("eOverdracht-overdrachtsbericht")

		assert.NotNil(t, result)
	})
}
