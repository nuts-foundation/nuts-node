package tree

import (
	"crypto/rand"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

// benchmarks
func BenchmarkIblt_BinaryMarshal(b *testing.B) {
	iblt, _ := getIbltWithRandomData(ibltNumBuckets, 128)
	for i := 0; i < b.N; i++ {
		_, _ = iblt.MarshalBinary()
	}
}

func BenchmarkIblt_BinaryUnmarshal(b *testing.B) {
	iblt, _ := getIbltWithRandomData(ibltNumBuckets, 128)
	bytes, _ := iblt.MarshalBinary()
	for i := 0; i < b.N; i++ {
		iblt = &Iblt{}
		_ = iblt.UnmarshalBinary(bytes)
	}
}

func getIbltWithRandomData(numBuckets, numHashes int) (*Iblt, map[hash.SHA256Hash]struct{}) {
	iblt := getEmptyTestIblt(numBuckets)
	// add hashes
	newRandomTx := func() hash.SHA256Hash {
		ref := hash.EmptyHash()
		_, _ = rand.Read(ref[:])
		return ref
	}
	hashes := make(map[hash.SHA256Hash]struct{}, numHashes)
	for i := 0; i < numHashes; i++ {
		ref := newRandomTx()
		_ = iblt.Insert(ref)
		hashes[ref] = struct{}{}
	}
	return iblt, hashes
}

func getEmptyTestIblt(numBuckets int) *Iblt {
	if numBuckets < int(ibltK) {
		panic("cannot have less than k buckets")
	}
	iblt := &Iblt{
		hc:      ibltHc,
		hk:      ibltHk,
		k:       ibltK,
		buckets: make([]*bucket, numBuckets),
	}
	for i := range iblt.buckets {
		iblt.buckets[i] = new(bucket)
	}
	return iblt
}

// tests iblt
func TestNewIblt(t *testing.T) {
	iblt := NewIblt(ibltNumBuckets)

	assert.Equal(t, ibltHc, iblt.hc)
	assert.Equal(t, ibltHk, iblt.hk)
	assert.Equal(t, ibltK, iblt.k)
	assert.Equal(t, ibltNumBuckets, len(iblt.buckets))
	assert.Equal(t, ibltNumBuckets, iblt.numBuckets())
	for i, b := range iblt.buckets {
		assert.Truef(t, b.isEmpty(), "bucket %d was not empty", i)
	}
	assert.True(t, equals(getEmptyTestIblt(ibltNumBuckets), iblt), "test function(s) invalid")
}

func equals(iblt1, iblt2 *Iblt) bool {
	_, err := iblt1.validate(iblt2)
	if err != nil {
		return false
	}
	for i := range iblt1.buckets {
		if !iblt1.buckets[i].equals(*iblt2.buckets[i]) {
			return false
		}
	}
	return true
}

func TestIblt_New(t *testing.T) {
	nBuckets := 6
	iblt := getEmptyTestIblt(nBuckets)
	h := hash.FromSlice([]byte{1})
	err := iblt.Insert(h)
	if !assert.NoError(t, err) {
		return
	}

	newIblt, ok := iblt.New().(*Iblt)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}

	assert.False(t, equals(iblt, newIblt))
	assert.True(t, equals(getEmptyTestIblt(nBuckets), newIblt))
}

func TestIblt_Clone(t *testing.T) {
	nBuckets := 6
	iblt := getEmptyTestIblt(nBuckets)
	h := hash.FromSlice([]byte{1})

	newIblt, ok := iblt.Clone().(*Iblt)
	if !assert.True(t, ok, "type assertion failed") {
		return
	}
	err := newIblt.Insert(h)
	if !assert.NoError(t, err) {
		return
	}

	assert.False(t, equals(iblt, newIblt))
	assert.True(t, equals(getEmptyTestIblt(nBuckets), iblt))
}

func TestIblt_Insert(t *testing.T) {
	iblt := getEmptyTestIblt(ibltNumBuckets)
	h := hash.FromSlice([]byte{1})
	bExp := bucket{
		count:   1,
		hashSum: iblt.hashKey(h),
		keySum:  h,
	}

	err := iblt.Insert(h)

	if assert.NoError(t, err) {
		return
	}
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
	iblt := getEmptyTestIblt(int(ibltK))
	h := hash.FromSlice([]byte{1})
	bExp := bucket{
		count:   -1,
		hashSum: iblt.hashKey(h),
		keySum:  h,
	}

	err := iblt.Insert(h)

	if assert.NoError(t, err) {
		return
	}
	for i, b := range iblt.buckets {
		assert.Truef(t, b.equals(bExp), "bucket %d did not match", i)
	}
}

func TestIblt_validate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		iblt1 := getEmptyTestIblt(int(ibltK))
		iblt2 := getEmptyTestIblt(int(ibltK))

		out, err := iblt1.validate(iblt2)

		assert.NoError(t, err)
		assert.NotNil(t, out)
	})

	t.Run("fail - data types don't match", func(t *testing.T) {
		iblt := getEmptyTestIblt(int(ibltK))
		notIblt := &Xor{}

		_, err := iblt.validate(notIblt)

		assert.EqualError(t, err, "other invalid - expected type *tree.Iblt, got *tree.Xor")
	})

	t.Run("fail - hc don't match", func(t *testing.T) {
		iblt1 := getEmptyTestIblt(int(ibltK))
		iblt2 := getEmptyTestIblt(int(ibltK))
		iblt2.hc++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "hc do not match, expected (0) got (1)")
	})

	t.Run("fail - hk don't match", func(t *testing.T) {
		iblt1 := getEmptyTestIblt(int(ibltK))
		iblt2 := getEmptyTestIblt(int(ibltK))
		iblt2.hk++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "hk do not match, expected (1) got (2)")
	})

	t.Run("fail - k don't match", func(t *testing.T) {
		iblt1 := getEmptyTestIblt(int(ibltK))
		iblt2 := getEmptyTestIblt(int(ibltK))
		iblt2.k++

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "unequal number of k, expected (6) got (7)")
	})

	t.Run("fail - #buckets don't match", func(t *testing.T) {
		iblt1 := getEmptyTestIblt(10)
		iblt2 := getEmptyTestIblt(11)

		_, err := iblt1.validate(iblt2)

		assert.EqualError(t, err, "number of buckets do not match, expected (10) got (11)")
	})
}

func TestIblt_Add(t *testing.T) {
	t.Run("ok - Add two *iblt", func(t *testing.T) {
		h1, h2 := hash.FromSlice([]byte{1}), hash.FromSlice([]byte{2})
		iblt1, iblt2, ibltAdd := getEmptyTestIblt(int(ibltK)), getEmptyTestIblt(int(ibltK)), getEmptyTestIblt(int(ibltK))
		_ = iblt1.Insert(h1)
		_ = iblt2.Insert(h2)
		_ = ibltAdd.Insert(h1)
		_ = ibltAdd.Insert(h2)

		err := iblt1.Add(iblt2)

		assert.NoError(t, err)
		assert.True(t, equals(iblt1, ibltAdd))
	})

	t.Run("fail - make sure validate is called", func(t *testing.T) {
		iblt1, iblt2 := getEmptyTestIblt(10), getEmptyTestIblt(20)

		err := iblt1.Add(iblt2)

		assert.EqualError(t, err, "number of buckets do not match, expected (10) got (20)")
	})
}

func TestIblt_Subtract(t *testing.T) {
	t.Run("ok - Add two *iblt", func(t *testing.T) {
		h1, h2 := hash.FromSlice([]byte{1}), hash.FromSlice([]byte{2})
		iblt1, iblt2, ibltSubtract := getEmptyTestIblt(int(ibltK)), getEmptyTestIblt(int(ibltK)), getEmptyTestIblt(int(ibltK))
		_ = iblt1.Insert(h1)
		_ = iblt2.Insert(h2)
		_ = ibltSubtract.Insert(h1)
		_ = ibltSubtract.Delete(h2)

		err := iblt1.Subtract(iblt2)

		assert.NoError(t, err)
		assert.True(t, equals(iblt1, ibltSubtract))
	})

	t.Run("fail - make sure validate is called", func(t *testing.T) {
		iblt1, iblt2 := getEmptyTestIblt(10), getEmptyTestIblt(20)

		err := iblt1.Subtract(iblt2)

		assert.EqualError(t, err, "number of buckets do not match, expected (10) got (20)")
	})
}

func TestIblt_Decode(t *testing.T) {

	t.Run("ok - Inserts only", func(t *testing.T) {
		numHashes := 3
		iblt, inserts := getIbltWithRandomData(ibltNumBuckets, numHashes)

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
		ibltIns, inserts := getIbltWithRandomData(ibltNumBuckets, numHashes)
		ibltDels, deletes := getIbltWithRandomData(ibltNumBuckets, numHashes)
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

	t.Run("fail - too many hashes", func(t *testing.T) {
		iblt, _ := getIbltWithRandomData(ibltNumBuckets, ibltNumBuckets)
		clone := iblt.Clone().(*Iblt)

		remaining, _, err := iblt.Decode()
		for _, r := range remaining {
			_ = iblt.Insert(r)
		}

		assert.ErrorIs(t, err, ErrDecodeNotPossible)
		assert.True(t, equals(clone, iblt), "failed to recover")
	})

	t.Run("fail - hash inserted twice", func(t *testing.T) {
		h := hash.FromSlice([]byte("random hash"))
		iblt := getEmptyTestIblt(ibltNumBuckets)
		_ = iblt.Insert(h)
		_ = iblt.Insert(h)

		_, _, err := iblt.Decode()

		assert.ErrorIs(t, err, ErrDecodeNotPossible)
	})
}

func TestIblt_MarshalBinary(t *testing.T) {
	hash1, _, hash1BucketBytes := marshalBucketWithHash1()
	iblt := getEmptyTestIblt(int(ibltK))
	_ = iblt.Insert(hash1)

	bs, err := iblt.MarshalBinary()

	assert.NoError(t, err)

	for i := 0; i < int(ibltK); i++ {
		assert.Equal(t, hash1BucketBytes, bs[i*bucketBytes:(i+1)*bucketBytes])
	}
}

func TestIblt_UnmarshalBinary(t *testing.T) {
	_, hash1Bucket, hash1BucketBytes := marshalBucketWithHash1()
	ibltExpected := getEmptyTestIblt(int(ibltK))
	iblt := ibltExpected.New().(*Iblt)
	var data []byte
	for i := 0; i < int(ibltK); i++ {
		data = append(data, hash1BucketBytes...)
		ibltExpected.buckets[i] = hash1Bucket.clone()
	}

	err := iblt.UnmarshalBinary(data)

	assert.NoError(t, err)
	assert.True(t, equals(ibltExpected, iblt))
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
		assert.True(t, b.equals(*hash1Bucket))
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
