package statuslist2021

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func TestBitstring_Bit(t *testing.T) {
	bs := Bitstring{33} // 33 => 00100001
	type test struct {
		index int
		isSet bool
		err   error
	}

	tt := []test{
		{-1, false, ErrIndexNotInBitstring},
		{0, false, nil},
		{1, false, nil},
		{2, true, nil},
		{3, false, nil},
		{4, false, nil},
		{5, false, nil},
		{6, false, nil},
		{7, true, nil},
		{8, false, ErrIndexNotInBitstring},
	}
	for _, tc := range tt {
		v, err := bs.Bit(tc.index)
		assert.ErrorIs(t, err, tc.err)
		assert.Equal(t, tc.isSet, v)
	}
}

func TestBitstring_SetBit(t *testing.T) {
	t.Run("ok - set value", func(t *testing.T) {
		bs := Bitstring{0}
		assert.NoError(t, bs.SetBit(2, true))
		assert.NoError(t, bs.SetBit(2, true)) // applies value, not a simple bit flip
		assert.NoError(t, bs.SetBit(7, true))
		assert.Equal(t, Bitstring{33}, bs) // 33 => 00100001
	})
	t.Run("ok - unset value", func(t *testing.T) {
		bs := Bitstring{33} // 33 => 00100001
		assert.NoError(t, bs.SetBit(2, false))
		assert.NoError(t, bs.SetBit(2, false)) // applies value, not a simple bit flip
		assert.Equal(t, Bitstring{1}, bs)
	})
	t.Run("error - index OOB", func(t *testing.T) {
		bs := Bitstring{0} // single byte
		assert.ErrorIs(t, bs.SetBit(-1, true), ErrIndexNotInBitstring)
		assert.NoError(t, bs.SetBit(0, true))
		assert.ErrorIs(t, bs.SetBit(8, true), ErrIndexNotInBitstring)
	})
}

func Test_CompressExpand(t *testing.T) {
	t.Run("ok - empty bitstring from example", func(t *testing.T) {
		// this EncodedList comes from the StatusList2021example https://www.w3.org/TR/2023/WD-vc-status-list-20230427/
		exampleEncodedList := "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
		bs := NewBitstring()

		expanded, err := Expand(exampleEncodedList)
		assert.NoError(t, err)
		assert.Len(t, *bs, len(expanded), "comparison invalid if these are not the same (16kB)")
		assert.Equal(t, *bs, expanded)
	})
	t.Run("ok - input>>Compress>>Expand == input", func(t *testing.T) {
		// make bitstring with random flags
		bs := *NewBitstring()
		assert.Equal(t, bs, *NewBitstring())
		for i := 0; i < 10; i++ {
			n := rand.Intn(defaultBitstringLengthInBytes * 8)
			assert.NoError(t, bs.SetBit(n, true))
		}
		assert.NotEqual(t, bs, *NewBitstring())

		// compress the input
		compressed, err := Compress(bs)
		require.NoError(t, err)
		// GZIP can contain some platform specific values meaning that we cannot compare it to a hardcoded result
		compressedEmpty, err := Compress(*NewBitstring())
		require.NoError(t, err)
		assert.NotEqual(t, compressed, compressedEmpty)

		// expand compressed and validate against original
		expanded, err := Expand(compressed)
		assert.NoError(t, err)
		assert.Equal(t, bs, expanded)
	})
}
