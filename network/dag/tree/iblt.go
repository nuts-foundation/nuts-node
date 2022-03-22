package tree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/twmb/murmur3"
)

const (
	ibltNumBuckets = 1024
	ibltHc         = uint64(0)
	ibltHk         = uint32(1)
	ibltK          = uint8(6)
	bucketBytes    = 44 // = int32 + uint64 + hash.SHA256HashSize
)

// ErrDecodeNotPossible is returned when the Iblt cannot be decoded.
var ErrDecodeNotPossible = errors.New("decode failed")

/*
Iblt implements an Invertible Bloom Filter, which is the special case of an IBLT where the key-value pair consist of a key-hash(key) pair.
The hash(key) value ensures correct decoding after subtraction of two IBLTs. Iblt is not thread-safe.
	- Goodrich, Michael T., and Michael Mitzenmacher. "Invertible bloom lookup tables." http://arxiv.org/pdf/1101.2245
	- Eppstein, David, et al. "What's the difference?: efficient set reconciliation without prior context." http://conferences.sigcomm.org/sigcomm/2011/papers/sigcomm/p218.pdf
*/
type Iblt struct {
	hc      uint64
	hk      uint32
	k       uint8
	buckets []*bucket
}

// NewIblt returns an *Iblt with default settings and specified number of buckets.
func NewIblt(numBuckets int) *Iblt {
	return &Iblt{
		buckets: makeBuckets(numBuckets),
		hc:      ibltHc,
		hk:      ibltHk,
		k:       ibltK,
	}
}

func (i Iblt) New() Data {
	return NewIblt(i.numBuckets())
}

func (i Iblt) Clone() Data {
	tmpBuckets := makeBuckets(i.numBuckets())
	for idx, b := range i.buckets {
		tmpBuckets[idx] = b.clone()
	}
	i.buckets = tmpBuckets
	return &i
}

func (i *Iblt) Insert(ref hash.SHA256Hash) error {
	keyHash := i.hashKey(ref)
	for _, h := range i.bucketIndices(keyHash) {
		i.buckets[h].insert(ref, keyHash)
	}
	return nil
}

// Delete subtracts the key from the iblt and is the inverse of Insert.
func (i *Iblt) Delete(key hash.SHA256Hash) error {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.buckets[h].delete(key, keyHash)
	}
	return nil
}

func (i *Iblt) Add(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx, b := range i.buckets {
		b.add(o.buckets[idx])
	}
	return nil
}

func (i *Iblt) Subtract(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx, b := range i.buckets {
		b.subtract(o.buckets[idx])
	}
	return nil
}

// validate returns other as an *iblt if it is compatible with self, or an error if not.
func (i Iblt) validate(other Data) (*Iblt, error) {
	// validate datatype
	o, ok := other.(*Iblt)
	if !ok {
		return nil, fmt.Errorf("other invalid - expected type %T, got %T", &i, other)
	}

	// validate format
	if i.numBuckets() != o.numBuckets() {
		return nil, fmt.Errorf("number of buckets do not match, expected (%d) got (%d)", i.numBuckets(), o.numBuckets())
	}
	if i.hc != o.hc {
		return nil, fmt.Errorf("hc do not match, expected (%d) got (%d)", i.hc, o.hc)
	}
	if i.hk != o.hk {
		return nil, fmt.Errorf("hk do not match, expected (%d) got (%d)", i.hk, o.hk)
	}
	if i.k != o.k {
		return nil, fmt.Errorf("unequal number of k, expected (%d) got (%d)", i.k, o.k)
	}

	// valid
	return o, nil
}

// Decode tries to deconstruct the iblt into hashes remaining (positive entries) and missing (negative entries) from the iblt.
// Decode is destructive to the iblt. If decoding fails with ErrDecodeNotPossible, the original iblt can be recovered by
// Insert-ing all remaining and Delete-ing all missing hashes. Any other error is unrecoverable.
func (i *Iblt) Decode() (remaining []hash.SHA256Hash, missing []hash.SHA256Hash, err error) {
	for {
		updated := false

		// peel off pures (count == ±1)
		for _, b := range i.buckets {
			if (b.count == 1 || b.count == -1) && i.hashKey(b.keySum) == b.hashSum {
				if b.count == 1 {
					remaining = append(remaining, b.keySum)
					err = i.Delete(b.keySum)
				} else { // b.count == -1
					missing = append(missing, b.keySum)
					err = i.Insert(b.keySum)
				}
				if err != nil {
					return nil, nil, err
				}
				updated = true
			}
		}

		// if no pures exist, the iblt is empty or cannot be decoded
		if !updated {
			for _, b := range i.buckets {
				if !b.isEmpty() {
					return remaining, missing, ErrDecodeNotPossible
				}
			}
			return remaining, missing, nil
		}
	}
}

func (i Iblt) numBuckets() int {
	return len(i.buckets)
}

func makeBuckets(numBuckets int) []*bucket {
	buckets := make([]*bucket, numBuckets)
	for i := 0; i < numBuckets; i++ {
		buckets[i] = new(bucket)
	}
	return buckets
}

func (i Iblt) bucketIndices(hash uint64) []uint32 {
	bucketUsed := make(map[uint32]bool, i.k)
	var indices []uint32
	hashKeyBytes, nextBytes := make([]byte, 8), make([]byte, 4)
	byteOrder().PutUint64(hashKeyBytes, hash)
	next := murmur3.SeedSum32(i.hk, hashKeyBytes)
	for len(indices) < int(i.k) {
		bucketId := next % uint32(i.numBuckets())
		if !bucketUsed[bucketId] {
			indices = append(indices, bucketId)
			bucketUsed[bucketId] = true
		}
		byteOrder().PutUint32(nextBytes, next)
		next = murmur3.SeedSum32(i.hk, nextBytes)
	}
	return indices
}

func (i Iblt) hashKey(key hash.SHA256Hash) uint64 {
	return murmur3.SeedSum64(i.hc, key.Slice())
}

func (i Iblt) MarshalBinary() ([]byte, error) {
	data := make([]byte, i.numBuckets()*bucketBytes)
	for idx, b := range i.buckets {
		bs, err := b.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[idx*bucketBytes:], bs)
	}
	return data, nil
}

func (i *Iblt) UnmarshalBinary(data []byte) error {
	numBuckets := len(data) / bucketBytes
	if len(data) != numBuckets*bucketBytes {
		return errors.New("invalid data length")
	}
	buf := bytes.NewBuffer(data)
	i.hc = ibltHc
	i.hk = ibltHk
	i.k = ibltK
	i.buckets = makeBuckets(numBuckets)
	for j := 0; j < i.numBuckets(); j++ {
		err := i.buckets[j].UnmarshalBinary(buf.Next(bucketBytes))
		if err != nil {
			return fmt.Errorf("unmarshalling failed - %w", err)
		}
	}
	return nil
}

// bucket
type bucket struct {
	// count is signed to allow for negative counts after subtraction
	count   int32           // #1
	hashSum uint64          // #2
	keySum  hash.SHA256Hash // #3
}

func (b *bucket) insert(key hash.SHA256Hash, hash uint64) {
	b.count++
	b.update(key, hash)
}

func (b *bucket) delete(key hash.SHA256Hash, hash uint64) {
	b.count--
	b.update(key, hash)
}

func (b *bucket) add(o *bucket) {
	b.count += o.count
	b.update(o.keySum, o.hashSum)
}

func (b *bucket) subtract(o *bucket) {
	b.count -= o.count
	b.update(o.keySum, o.hashSum)
}

func (b *bucket) update(key hash.SHA256Hash, hash uint64) {
	xor(b.keySum[:], b.keySum[:], key[:])
	b.hashSum ^= hash
}

func (b bucket) clone() *bucket {
	return &b
}

func (b bucket) isEmpty() bool {
	return b.equals(*new(bucket))
}

func (b bucket) equals(o bucket) bool {
	return b == o
}

func (b bucket) String() string {
	return fmt.Sprintf("{count:%d keySum:%s hashSum:%d}", b.count, b.keySum, b.hashSum)
}

func (b bucket) MarshalBinary() ([]byte, error) {
	bs := make([]byte, bucketBytes)
	byteOrder().PutUint32(bs, uint32(b.count)) // #1
	byteOrder().PutUint64(bs[4:], b.hashSum)   // #2
	copy(bs[12:], b.keySum.Clone().Slice())    // #3
	return bs, nil
}

func (b *bucket) UnmarshalBinary(data []byte) error {
	if len(data) != bucketBytes {
		return errors.New("invalid data length")
	}
	buf := bytes.NewBuffer(data)
	b.count = int32(byteOrder().Uint32(buf.Next(4)))         // #1
	b.hashSum = byteOrder().Uint64(buf.Next(8))              // #2
	b.keySum = hash.FromSlice(buf.Next(hash.SHA256HashSize)) // #3
	return nil
}

// byteOrder returns the binary.ByteOrder described in the specs.
// This guarantees Iblt generation is platform independent and allows decentralized comparison.
func byteOrder() binary.ByteOrder {
	return binary.LittleEndian
}
