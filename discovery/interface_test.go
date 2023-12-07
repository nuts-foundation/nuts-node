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

package discovery

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTag_Empty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.True(t, Tag("").Empty())
	})
	t.Run("not empty", func(t *testing.T) {
		assert.False(t, Tag("not empty").Empty())
	})
}

func TestTag_Timestamp(t *testing.T) {
	t.Run("invalid tag prefix", func(t *testing.T) {
		assert.Nil(t, Tag("invalid tag prefix").Timestamp("tag prefix"))
	})
	t.Run("not a number", func(t *testing.T) {
		assert.Nil(t, Tag("tag prefix").Timestamp("tag prefixnot a number"))
	})
	t.Run("invalid uint64", func(t *testing.T) {
		assert.Nil(t, Tag("tag prefix").Timestamp("tag prefix"))
	})
	t.Run("valid (small number)", func(t *testing.T) {
		assert.Equal(t, Timestamp(1), *Tag("tag prefix1").Timestamp("tag prefix"))
	})
	t.Run("valid (large number)", func(t *testing.T) {
		assert.Equal(t, Timestamp(1234567890), *Tag("tag prefix1234567890").Timestamp("tag prefix"))
	})
}

func TestTimestamp_Tag(t *testing.T) {
	assert.Equal(t, Tag("tag prefix1"), Timestamp(1).Tag("tag prefix"))
}

func TestTimestamp_Increment(t *testing.T) {
	assert.Equal(t, Timestamp(1), Timestamp(0).Increment())
	assert.Equal(t, Timestamp(2), Timestamp(1).Increment())
	assert.Equal(t, Timestamp(1234567890), Timestamp(1234567889).Increment())
}
