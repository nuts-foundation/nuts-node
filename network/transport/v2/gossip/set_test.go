/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package gossip

import (
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestUniqueList_Add(t *testing.T) {
	t.Run("adds entries to list and set", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.EmptyHash())

		assert.Equal(t, 1, u.list.Len())
		assert.Equal(t, u.list.Front(), u.set[hash.EmptyHash().String()])
	})

	t.Run("does not add when condition not met", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.EmptyHash(), func(u *uniqueList) bool {
			return false
		})

		assert.Equal(t, 0, u.list.Len())
	})
}

func TestUniqueList_Remove(t *testing.T) {
	t.Run("removes values from list and set", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.EmptyHash())
		u.Remove(hash.EmptyHash())

		assert.Equal(t, 0, u.list.Len())
		assert.Equal(t, 0, len(u.set))
	})

	t.Run("does not remove when condition not met", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.EmptyHash())
		u.Remove(hash.EmptyHash(), func(u *uniqueList) bool {
			return false
		})

		assert.Equal(t, 1, u.list.Len())
		assert.Equal(t, 1, len(u.set))
	})

}

func TestUniqueList_RemoveFront(t *testing.T) {
	t.Run("it removes the front value", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.SHA256Sum([]byte{1}))
		u.Add(hash.EmptyHash())
		u.RemoveFront()

		assert.Equal(t, 1, u.list.Len())
		assert.Equal(t, 1, len(u.set))
		assert.True(t, u.Contains(hash.EmptyHash()))
	})

	t.Run("it doesn't remove the front value if conditions not met", func(t *testing.T) {
		u := newUniqueList()

		u.Add(hash.SHA256Sum([]byte{1}))
		u.Add(hash.EmptyHash())
		u.RemoveFront(func(u *uniqueList) bool {
			return false
		})

		assert.Equal(t, 2, u.list.Len())
		assert.Equal(t, 2, len(u.set))
	})
}
