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

package usecase

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_doublyLinkedList_append(t *testing.T) {
	t.Run("1 entry", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		list.append(1)
		assert.Equal(t, 1, list.head.value)
		assert.Equal(t, 1, list.tail.value)
	})
	t.Run("2 entries", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		list.append(1)
		list.append(2)
		assert.Equal(t, 1, list.head.value)
		assert.Equal(t, 2, list.tail.value)
		assert.Equal(t, list.tail, list.head.next)
		assert.Equal(t, list.head, list.tail.prev)
	})
}

func Test_doublyLinkedList_empty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		assert.True(t, list.empty())
	})
	t.Run("non-empty", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		list.append(1)
		assert.False(t, list.empty())
	})
}

func Test_doublyLinkedList_remove(t *testing.T) {
	t.Run("remove head", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		first := list.append(1)
		list.append(2)
		list.remove(first)
		assert.Same(t, list.tail, list.head)
		assert.Equal(t, 2, list.head.value)
		assert.Nil(t, list.head.prev)
		assert.Nil(t, list.head.next)
	})
	t.Run("remove tail", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		list.append(1)
		last := list.append(2)
		list.remove(last)
		assert.Same(t, list.tail, list.head)
		assert.Equal(t, 1, list.head.value)
		assert.Nil(t, list.head.prev)
		assert.Nil(t, list.head.next)
	})
	t.Run("remove middle", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		first := list.append(1)
		middle := list.append(2)
		last := list.append(3)
		list.remove(middle)
		assert.Equal(t, 1, list.head.value)
		assert.Equal(t, 3, list.tail.value)
		assert.Same(t, first, list.head)
		assert.Same(t, last, list.tail)
		assert.Same(t, last, list.head.next)
		assert.Same(t, first, list.tail.prev)
	})
	t.Run("empty list after remove of last item", func(t *testing.T) {
		list := new(doublyLinkedList[int])
		first := list.append(1)
		second := list.append(2)
		list.remove(first)
		list.remove(second)
		assert.Nil(t, list.head)
		assert.Nil(t, list.tail)
		assert.True(t, list.empty())
	})
}
