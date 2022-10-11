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
	"bytes"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func getIbltWithRandomData(numHashes int) (*Iblt, map[hash.SHA256Hash]struct{}) {
	iblt := NewIblt()
	hashes := make(map[hash.SHA256Hash]struct{}, numHashes)
	for i := 0; i < numHashes; i++ {
		ref := hash.RandomHash()
		iblt.Insert(ref)
		hashes[ref] = struct{}{}
	}
	return iblt, hashes
}

// tests iblt
func TestNewIblt(t *testing.T) {
	iblt := NewIblt()
	expected := &Iblt{
		hc: ibltHc,
		hk: ibltHk,
		k:  ibltK,
	}

	assert.Equal(t, ibltHc, iblt.hc)
	assert.Equal(t, ibltHk, iblt.hk)
	assert.Equal(t, ibltK, iblt.k)
	assert.Equal(t, numBuckets, len(iblt.buckets))
	for i, b := range iblt.buckets {
		assert.Truef(t, b.isEmpty(), "bucket %d was not empty", i)
	}
	assert.True(t, equals(expected, iblt), "test function(s) invalid")
}

func equals(iblt1, iblt2 *Iblt) bool {
	_, err := iblt1.validate(iblt2)
	if err != nil {
		return false
	}
	for i := range iblt1.buckets {
		if !iblt1.buckets[i].equals(&iblt2.buckets[i]) {
			return false
		}
	}
	return true
}

func TestIblt_New(t *testing.T) {
	iblt := NewIblt()
	h := hash.FromSlice([]byte{1})
	iblt.Insert(h)

	newIblt, ok := iblt.New().(*Iblt)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}

	assert.False(t, equals(iblt, newIblt))
	assert.True(t, equals(NewIblt(), newIblt))
}

func TestIblt_Clone(t *testing.T) {
	iblt := NewIblt()
	h := hash.FromSlice([]byte{1})

	newIblt, ok := iblt.Clone().(*Iblt)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}
	newIblt.Insert(h)

	assert.False(t, equals(iblt, newIblt))
	assert.True(t, equals(NewIblt(), iblt))
}

func TestIblt_Insert(t *testing.T) {
	iblt := NewIblt()
	h := hash.FromSlice([]byte{1})
	bExp := &bucket{
		count:   1,
		hashSum: iblt.hashKey(h),
		keySum:  h,
	}

	iblt.Insert(h)

	numMatches := 0
	for _, b := range iblt.buckets {
		if b.equals(bExp) {
			numMatches++
		}
	}
	assert.Equal(t, int(iblt.k), numMatches)
	assert.NotEqual(t, uint64(0), bExp.hashSum)
}

func TestIblt_Delete(t *testing.T) {
	iblt := NewIblt()
	h := hash.FromSlice([]byte{1})
	bExp := &bucket{
		count:   -1,
		hashSum: iblt.hashKey(h),
		keySum:  h,
	}

	iblt.Delete(h)

	var counts uint8
	for idx := range iblt.buckets {
		if iblt.buckets[idx].equals(bExp) {
			counts++
		}
	}

	assert.Equal(t, ibltK, counts)
}

func TestIblt_validate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		iblt1 := NewIblt()
		iblt2 := NewIblt()

		out, err := iblt1.validate(iblt2)

		assert.NoError(t, err)
		assert.NotNil(t, out)
	})

	t.Run("fail - data types don't match", func(t *testing.T) {
		iblt := NewIblt()
		notIblt := &Xor{}

		_, err := iblt.validate(notIblt)

		assert.EqualError(t, err, "other invalid - expected type *tree.Iblt, got *tree.Xor")
	})

	t.Run("fail - hc don't match", func(t *testing.T) {
		iblt1 := NewIblt()
		iblt2 := NewIblt()
		iblt2.hc++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "hc do not match, expected (0) got (1)")
	})

	t.Run("fail - hk don't match", func(t *testing.T) {
		iblt1 := NewIblt()
		iblt2 := NewIblt()
		iblt2.hk++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "hk do not match, expected (1) got (2)")
	})

	t.Run("fail - k don't match", func(t *testing.T) {
		iblt1 := NewIblt()
		iblt2 := NewIblt()
		iblt2.k++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "unequal number of k, expected (6) got (7)")
	})
}

func TestIblt_Add(t *testing.T) {
	t.Run("ok - Add two *iblt", func(t *testing.T) {
		h1, h2 := hash.FromSlice([]byte{1}), hash.FromSlice([]byte{2})
		iblt1, iblt2, ibltAdd := NewIblt(), NewIblt(), NewIblt()
		iblt1.Insert(h1)
		iblt2.Insert(h2)
		ibltAdd.Insert(h1)
		ibltAdd.Insert(h2)

		err := iblt1.Add(iblt2)

		assert.NoError(t, err)
		assert.True(t, equals(iblt1, ibltAdd))
	})

	t.Run("fail - make sure validate is called", func(t *testing.T) {
		iblt1, iblt2 := NewIblt(), NewIblt()
		iblt2.k = ibltK + 1

		err := iblt1.Add(iblt2)

		assert.EqualError(t, err, "unequal number of k, expected (6) got (7)")
	})
}

func TestIblt_Subtract(t *testing.T) {
	t.Run("ok - Add two *iblt", func(t *testing.T) {
		h1, h2 := hash.FromSlice([]byte{1}), hash.FromSlice([]byte{2})
		iblt1, iblt2, ibltSubtract := NewIblt(), NewIblt(), NewIblt()
		iblt1.Insert(h1)
		iblt2.Insert(h2)
		ibltSubtract.Insert(h1)
		ibltSubtract.Delete(h2)

		err := iblt1.Subtract(iblt2)

		assert.NoError(t, err)
		assert.True(t, equals(iblt1, ibltSubtract))
	})

	t.Run("fail - make sure validate is called", func(t *testing.T) {
		iblt1, iblt2 := NewIblt(), NewIblt()
		iblt2.k = ibltK + 1

		err := iblt1.Subtract(iblt2)

		assert.EqualError(t, err, "unequal number of k, expected (6) got (7)")
	})
}

func TestIblt_Decode(t *testing.T) {

	t.Run("ok - Inserts only", func(t *testing.T) {
		numHashes := 3
		iblt, inserts := getIbltWithRandomData(numHashes)

		remaining, missing, err := iblt.Decode()

		assert.NoError(t, err)
		assert.Equal(t, 0, len(missing))
		assert.Equal(t, numHashes, len(remaining))
		for _, r := range remaining {
			_, ok := inserts[r]
			assert.True(t, ok)
		}
	})

	t.Run("ok - Inserts and Deletes", func(t *testing.T) {
		numHashes := 3
		ibltIns, inserts := getIbltWithRandomData(numHashes)
		ibltDels, deletes := getIbltWithRandomData(numHashes)
		_ = ibltIns.Subtract(ibltDels)

		remaining, missing, err := ibltIns.Decode()

		assert.NoError(t, err)
		assert.Equal(t, numHashes, len(remaining))
		assert.Equal(t, numHashes, len(missing))
		var ok bool
		for i := 0; i < numHashes; i++ {
			_, ok = inserts[remaining[i]]
			assert.True(t, ok)
			_, ok = deletes[missing[i]]
			assert.True(t, ok)
		}
	})

	t.Run("fail - loop detection", func(t *testing.T) {
		key := hash.FromSlice([]byte("looper"))
		iblt := NewIblt()
		iblt.Insert(key)
		keyHash := iblt.hashKey(key)
		// if the key-keyHash pair is missing from one of the buckets,
		// it will be remaining/missing in the iblt out of sync with the other buckets causing a loop.
		iblt.buckets[iblt.bucketIndices(keyHash)[0]].delete(key, keyHash)

		_, _, err := iblt.Decode()

		assert.Equal(t, ErrDecodeLoop, err)
	})

	t.Run("fail - too many hashes", func(t *testing.T) {
		iblt, _ := getIbltWithRandomData(numBuckets)
		clone := iblt.Clone().(*Iblt)

		remaining, _, err := iblt.Decode()
		for _, r := range remaining {
			iblt.Insert(r)
		}

		assert.ErrorIs(t, err, ErrDecodeNotPossible)
		assert.True(t, equals(clone, iblt), "failed to recover")
	})

	t.Run("fail - hash inserted twice", func(t *testing.T) {
		h := hash.FromSlice([]byte("random hash"))
		iblt := NewIblt()
		iblt.Insert(h)
		iblt.Insert(h)

		_, _, err := iblt.Decode()

		assert.ErrorIs(t, err, ErrDecodeNotPossible)
	})
}

func TestIblt_IsEmpty(t *testing.T) {
	t.Run("true - new iblt", func(t *testing.T) {
		iblt := NewIblt()

		assert.True(t, iblt.IsEmpty())
	})

	t.Run("false - insert", func(t *testing.T) {
		iblt := NewIblt()
		h := hash.FromSlice([]byte("test hash"))

		iblt.Insert(h)

		assert.False(t, iblt.IsEmpty())
	})

	t.Run("true - insert and delete same hash", func(t *testing.T) {
		iblt := NewIblt()
		h := hash.FromSlice([]byte("test hash"))

		iblt.Insert(h)
		iblt.Delete(h)

		assert.True(t, iblt.IsEmpty())
	})
}

func TestIblt_MarshalBinary(t *testing.T) {
	hash1, _, hash1BucketBytes := marshalBucketWithHash1()
	iblt := NewIblt()
	iblt.Insert(hash1)

	bs, err := iblt.MarshalBinary()

	assert.NoError(t, err)

	var count uint8
	for i := 0; i < len(iblt.buckets); i++ {
		if bytes.Equal(hash1BucketBytes, bs[i*bucketBytes:(i+1)*bucketBytes]) {
			count++
		}
	}
	assert.Equal(t, ibltK, count)
}

func TestIblt_UnmarshalBinary(t *testing.T) {
	_, hash1Bucket, hash1BucketBytes := marshalBucketWithHash1()
	ibltExpected := NewIblt()
	iblt := ibltExpected.New().(*Iblt)
	data := make([]byte, bucketBytes*numBuckets)

	for _, i := range []int{1, 45, 145, 465, 798, 1002} {
		copy(data[i*bucketBytes:], hash1BucketBytes)
		ibltExpected.buckets[i] = *hash1Bucket
	}

	err := iblt.UnmarshalBinary(data)

	assert.NoError(t, err)
	assert.Equal(t, ibltExpected, iblt)
	assert.False(t, iblt.IsEmpty())
}

// tests bucket
func TestBucket_MarshalBinary(t *testing.T) {
	_, hash1Bucket, hash1BucketBytes := marshalBucketWithHash1()
	bs, err := hash1Bucket.MarshalBinary()

	assert.NoError(t, err)
	assert.Equal(t, hash1BucketBytes, bs)
}

func TestBucket_UnmarshalBinary(t *testing.T) {
	t.Run("ok - unmarshal bucket", func(t *testing.T) {
		_, hash1Bucket, hash1BucketBytes := marshalBucketWithHash1()
		b := new(bucket)

		err := b.UnmarshalBinary(hash1BucketBytes)

		assert.NoError(t, err)
		assert.True(t, b.equals(hash1Bucket))
	})

	t.Run("fail - invalid data length", func(t *testing.T) {
		bs := []byte("invalid bucket length")
		b := new(bucket)

		err := b.UnmarshalBinary(bs)

		assert.EqualError(t, err, "invalid data length")
	})
}

// creates a bucket containing hash.FromSlice([]byte{1})
func marshalBucketWithHash1() (hash.SHA256Hash, *bucket, []byte) {
	hash1 := hash.FromSlice([]byte{1})
	hash1Bucket := &bucket{
		count:   1,
		hashSum: uint64(6332109210212100501),
		keySum:  hash1,
	}
	hash1BucketBytes := []byte{1, 0, 0, 0, 149, 233, 171, 25, 199, 43, 224, 87, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	return hash1, hash1Bucket, hash1BucketBytes
}
