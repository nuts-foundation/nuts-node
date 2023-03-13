/*
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

package hash

import (
	"encoding"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

var _ fmt.Stringer = SHA256Hash{}
var _ encoding.TextMarshaler = SHA256Hash{}

func TestHash_Empty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.True(t, EmptyHash().Empty())
	})
	t.Run("non empty", func(t *testing.T) {
		h, err := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		require.NoError(t, err)
		assert.False(t, h.Empty())
	})
	t.Run("returns new hash every time", func(t *testing.T) {
		h1 := EmptyHash()
		h2 := EmptyHash()
		assert.True(t, h1.Equals(h2))
		h1[0] = 10
		assert.False(t, h1.Equals(h2))
	})
}

func TestHash_Slice(t *testing.T) {
	t.Run("slice parsed hash", func(t *testing.T) {
		h, err := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		require.NoError(t, err)
		assert.Equal(t, h, FromSlice(h.Slice()))
	})
	t.Run("returns new slice every time", func(t *testing.T) {
		h, _ := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		s1 := h.Slice()
		s2 := h.Slice()
		assert.Equal(t, s1, s2)
		s1[0] = 10
		assert.NotEqual(t, s1, s2)
	})
}

func TestParseHex(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		hash, err := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		assert.NoError(t, err)
		assert.Equal(t, "452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620", hash.String())
	})
	t.Run("ok - empty string input", func(t *testing.T) {
		hash, err := ParseHex("")
		assert.NoError(t, err)
		assert.True(t, hash.Empty())
	})
	t.Run("error - invalid input", func(t *testing.T) {
		hash, err := ParseHex("a23da")
		assert.Error(t, err)
		assert.True(t, hash.Empty())
	})
	t.Run("error - incorrect length", func(t *testing.T) {
		hash, err := ParseHex("383c9da631bd120169e82b0679e4c2e8d5050894383c9da631bd120169e82b0679e4c2e8d5050894")
		assert.EqualError(t, err, "incorrect hash length (40)")
		assert.True(t, hash.Empty())
	})
}

func TestSHA256Hash(t *testing.T) {
	s := "hi"
	h := SHA256Sum([]byte(s))

	assert.Equal(t, "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", h.String())
}

func TestSHA256Hash_Clone(t *testing.T) {
	s := "hi"
	h := SHA256Sum([]byte(s))
	c := h.Clone()

	assert.Equal(t, "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", c.String())
}

func TestSHA256Hash_MarshalJSON(t *testing.T) {
	s := "452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620"
	h, _ := ParseHex(s)

	t.Run("ok", func(t *testing.T) {
		bytes, err := json.Marshal(h)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("\"%s\"", s), string(bytes))
	})
}

func TestSHA256Hash_UnmarshalJSON(t *testing.T) {
	s := "452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620"
	j := fmt.Sprintf("\"%s\"", s)

	t.Run("ok", func(t *testing.T) {
		h := EmptyHash()
		err := json.Unmarshal([]byte(j), &h)
		require.NoError(t, err)
		assert.Equal(t, s, h.String())
	})

	t.Run("error - wrong hex", func(t *testing.T) {
		h := EmptyHash()
		err := json.Unmarshal([]byte(""), &h)

		assert.Error(t, err)
	})
}

func TestHash_Equals(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		h1, _ := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		h2, _ := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		assert.True(t, h1.Equals(h2))
	})
	t.Run("not equal", func(t *testing.T) {
		h1 := EmptyHash()
		h2, _ := ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		assert.False(t, h1.Equals(h2))
	})
}

func TestHash_Compare(t *testing.T) {
	t.Run("smaller", func(t *testing.T) {
		h1, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000001")
		h2, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000002")
		assert.Equal(t, -1, h1.Compare(h2))
	})
	t.Run("equal", func(t *testing.T) {
		h1, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000001")
		h2, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000001")
		assert.Equal(t, 0, h1.Compare(h2))
	})
	t.Run("larger", func(t *testing.T) {
		h1, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000002")
		h2, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000001")
		assert.Equal(t, 1, h1.Compare(h2))
	})
}

func TestHash_Xor(t *testing.T) {
	h0 := EmptyHash()
	h1 := FromSlice([]byte{1})
	h2 := FromSlice([]byte{2})
	expected := FromSlice([]byte{3})

	actual := h0.Xor(h1, h2)

	assert.Equal(t, EmptyHash(), h0, "original Hash should not change")
	assert.Equal(t, expected, actual)
}

func TestHash_RandomHash(t *testing.T) {
	h1 := RandomHash()
	h2 := RandomHash()

	assert.False(t, h1.Equals(h2))
	assert.False(t, h1.Empty())
	assert.False(t, h2.Empty())
}
