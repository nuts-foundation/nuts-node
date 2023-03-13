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

package tree

import (
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTwoHashPlusXor() (h1 hash.SHA256Hash, h2 hash.SHA256Hash, hXor hash.SHA256Hash) {
	h1 = hash.FromSlice([]byte{1})
	h2 = hash.FromSlice([]byte{2})
	hXor = hash.FromSlice([]byte{3})
	return
}

func TestXor_New(t *testing.T) {
	xor1 := Xor{}
	h1 := hash.FromSlice([]byte{1})
	xor1.Insert(h1)

	xorN, ok := xor1.New().(*Xor)
	require.True(t, ok, "type assertion failed")

	assert.Equal(t, Xor(h1), xor1)
	assert.Equal(t, Xor{}, *xorN)
}

func TestXor_Clone(t *testing.T) {
	xor1 := Xor{}
	h1, h2, hXor := getTwoHashPlusXor()
	xor1.Insert(h1)

	xorN, ok := xor1.Clone().(*Xor)
	require.True(t, ok, "type assertion failed")
	xorN.Insert(h2)

	assert.Equal(t, h1, xor1.Hash())
	assert.Equal(t, hXor, xorN.Hash())
}

func TestXor_Insert(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()

	t.Run("ok - insert 1 hash", func(t *testing.T) {
		x := Xor{}
		x.Insert(h1)

		assert.Equal(t, h1, x.Hash())
	})

	t.Run("ok - insert 2 hashes", func(t *testing.T) {
		x := Xor{}
		x.Insert(h1)
		x.Insert(h2)

		assert.Equal(t, hXor, x.Hash())
	})

	t.Run("ok - insert hash twice", func(t *testing.T) {
		x := Xor{}
		x.Insert(h1)
		x.Insert(h1)

		assert.Equal(t, Xor{}, x)
	})
}

func TestXor_Delete(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()

	t.Run("ok - delete 1 hash", func(t *testing.T) {
		x := Xor{}
		x.Delete(h1)

		assert.Equal(t, h1, x.Hash())
	})

	t.Run("ok - delete 2 hashes", func(t *testing.T) {
		x := Xor{}
		x.Delete(h1)
		x.Delete(h2)

		assert.Equal(t, hXor, x.Hash())
	})

	t.Run("ok - delete hash twice", func(t *testing.T) {
		x := Xor{}
		x.Delete(h1)
		x.Delete(h1)

		assert.Equal(t, Xor{}, x)
	})
}

func TestXor_Add(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()

	t.Run("ok - Add two Xor", func(t *testing.T) {
		x1 := Xor(h1)
		x2 := Xor(h2)

		err := x1.Add(&x2)

		assert.NoError(t, err)
		assert.Equal(t, hXor, x1.Hash())
	})

	t.Run("fail - Add non *Xor", func(t *testing.T) {
		x1 := Xor(h1)
		dummy := &Iblt{}

		err := x1.Add(dummy)

		assert.EqualError(t, err, "data type mismatch - expected *tree.Xor, got *tree.Iblt")
		assert.Equal(t, h1, x1.Hash())
	})
}

func TestXor_Subtract(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()

	t.Run("ok - Subtract two Xor", func(t *testing.T) {
		x1 := Xor(h1)
		x2 := Xor(h2)

		err := x1.Add(&x2)

		assert.NoError(t, err)
		assert.Equal(t, hXor, x1.Hash())
	})

	t.Run("fail - Subtract non *Xor", func(t *testing.T) {
		x1 := Xor(h1)
		dummy := &Iblt{}

		err := x1.Add(dummy)

		assert.EqualError(t, err, "data type mismatch - expected *tree.Xor, got *tree.Iblt")
		assert.Equal(t, Xor(h1), x1)
	})
}

func TestXor_IsEmpty(t *testing.T) {
	t.Run("is empty", func(t *testing.T) {
		x := NewXor()
		assert.True(t, x.Empty())
	})

	t.Run("is not empty", func(t *testing.T) {
		x := Xor(hash.FromSlice([]byte("not empty")))
		assert.False(t, x.Empty())
	})
}

func TestXor_MarshalBinary(t *testing.T) {
	h1 := hash.FromSlice([]byte{1})
	x := Xor(h1)

	raw, err := x.MarshalBinary()

	assert.NoError(t, err)
	assert.Equal(t, h1.Slice(), raw)
}

func TestXor_UnmarshalBinary(t *testing.T) {
	t.Run("ok - unmarshal hash", func(t *testing.T) {
		h1 := hash.FromSlice([]byte{1})
		x := Xor{}

		err := x.UnmarshalBinary(h1.Slice())

		assert.NoError(t, err)
		assert.Equal(t, Xor(h1), x)
	})

	t.Run("fail - invalid data length", func(t *testing.T) {
		bs := []byte("invalid hash length")
		x := Xor{}

		err := x.UnmarshalBinary(bs)

		assert.EqualError(t, err, "invalid data length")
	})
}
