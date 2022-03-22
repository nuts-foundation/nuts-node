package tree

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestXor_xor(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()
	out := Xor{}

	xor(out[:], h1[:], h2[:])

	assert.Equal(t, hXor, out.Hash())
	assert.NotEqual(t, h1, out) // sanity check
}

func getTwoHashPlusXor() (h1 hash.SHA256Hash, h2 hash.SHA256Hash, hXor hash.SHA256Hash) {
	h1 = hash.FromSlice([]byte{1})
	h2 = hash.FromSlice([]byte{2})
	hXor = hash.FromSlice([]byte{3})
	return
}

func TestXor_New(t *testing.T) {
	xor1 := Xor{}
	h1 := hash.FromSlice([]byte{1})
	err := xor1.Insert(h1)
	if !assert.NoError(t, err) {
		return
	}

	xorN, ok := xor1.New().(*Xor)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}

	assert.Equal(t, Xor(h1), xor1)
	assert.Equal(t, Xor{}, *xorN)
}

func TestXor_Clone(t *testing.T) {
	xor1 := Xor{}
	h1, h2, hXor := getTwoHashPlusXor()
	err := xor1.Insert(h1)
	if !assert.NoError(t, err) {
		return
	}

	xorN, ok := xor1.Clone().(*Xor)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}
	err = xorN.Insert(h2)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, h1, xor1.Hash())
	assert.Equal(t, hXor, xorN.Hash())
}

func TestXor_Insert(t *testing.T) {
	h1, h2, hXor := getTwoHashPlusXor()

	t.Run("ok - insert 1 hash", func(t *testing.T) {
		x := Xor{}
		err := x.Insert(h1)

		assert.NoError(t, err)
		assert.Equal(t, h1, x.Hash())
	})

	t.Run("ok - insert 2 hashes", func(t *testing.T) {
		x := Xor{}
		_ = x.Insert(h1)
		err := x.Insert(h2)

		assert.NoError(t, err)
		assert.Equal(t, hXor, x.Hash())
	})

	t.Run("ok - insert hash twice", func(t *testing.T) {
		x := Xor{}
		_ = x.Insert(h1)
		err := x.Insert(h1)

		assert.NoError(t, err)
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
