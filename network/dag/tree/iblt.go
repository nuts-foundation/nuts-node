package tree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/spaolacci/murmur3"
)

const (
	ibltNumBuckets = 1024
	ibltHc         = uint32(0)
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
	Hc      uint32    `json:"Hc"`
	Hk      uint32    `json:"Hk"`
	K       uint8     `json:"K"`
	Buckets []*bucket `json:"buckets"`
}

// NewIblt returns an *Iblt with default settings and specified number of buckets.
func NewIblt(numBuckets int) *Iblt {
	return &Iblt{
		Buckets: makeBuckets(numBuckets),
		Hc:      ibltHc,
		Hk:      ibltHk,
		K:       ibltK,
	}
}

func (i Iblt) New() Data {
	return NewIblt(i.numBuckets())
}

func (i Iblt) Clone() Data {
	tmpBuckets := makeBuckets(i.numBuckets())
	for idx, b := range i.Buckets {
		tmpBuckets[idx] = b.clone()
	}
	i.Buckets = tmpBuckets
	return &i
}

func (i *Iblt) Insert(ref hash.SHA256Hash) error {
	keyHash := i.hashKey(ref)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].insert(ref, keyHash)
	}
	return nil
}

// Delete subtracts the key from the iblt and is the inverse of Insert.
func (i *Iblt) Delete(key hash.SHA256Hash) error {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].delete(key, keyHash)
	}
	return nil
}

func (i *Iblt) Add(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx, b := range i.Buckets {
		b.add(o.Buckets[idx])
	}
	return nil
}

func (i *Iblt) Subtract(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx, b := range i.Buckets {
		b.subtract(o.Buckets[idx])
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
		return nil, fmt.Errorf("number of Buckets do not match, expected (%d) got (%d)", i.numBuckets(), o.numBuckets())
	}
	if i.Hc != o.Hc {
		return nil, fmt.Errorf("Hc do not match, expected (%d) got (%d)", i.Hc, o.Hc)
	}
	if i.Hk != o.Hk {
		return nil, fmt.Errorf("Hk do not match, expected (%d) got (%d)", i.Hk, o.Hk)
	}
	if i.K != o.K {
		return nil, fmt.Errorf("unequal number of K, expected (%d) got (%d)", i.K, o.K)
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
		for _, b := range i.Buckets {
			if (b.Count == 1 || b.Count == -1) && i.hashKey(b.KeySum) == b.HashSum {
				if b.Count == 1 {
					remaining = append(remaining, b.KeySum)
					err = i.Delete(b.KeySum)
				} else { // b.count == -1
					missing = append(missing, b.KeySum)
					err = i.Insert(b.KeySum)
				}
				if err != nil {
					return nil, nil, err
				}
				updated = true
			}
		}

		// if no pures exist, the iblt is empty or cannot be decoded
		if !updated {
			for _, b := range i.Buckets {
				if !b.isEmpty() {
					return remaining, missing, ErrDecodeNotPossible
				}
			}
			return remaining, missing, nil
		}
	}
}

func (i Iblt) numBuckets() int {
	return len(i.Buckets)
}

func makeBuckets(numBuckets int) []*bucket {
	buckets := make([]*bucket, numBuckets)
	for i := 0; i < numBuckets; i++ {
		buckets[i] = new(bucket)
	}
	return buckets
}

func (i Iblt) bucketIndices(hash uint64) []uint32 {
	bucketUsed := make(map[uint32]bool, i.K)
	var indices []uint32
	hashKeyBytes, nextBytes := make([]byte, 8), make([]byte, 4)
	binary.LittleEndian.PutUint64(hashKeyBytes, hash)
	next := murmur3.Sum32WithSeed(hashKeyBytes, i.Hk)
	for len(indices) < int(i.K) {
		bucketId := next % uint32(i.numBuckets())
		if !bucketUsed[bucketId] {
			indices = append(indices, bucketId)
			bucketUsed[bucketId] = true
		}
		binary.LittleEndian.PutUint32(nextBytes, next)
		next = murmur3.Sum32WithSeed(nextBytes, i.Hk)
	}
	return indices
}

func (i Iblt) hashKey(key hash.SHA256Hash) uint64 {
	return murmur3.Sum64WithSeed(key.Slice(), i.Hc)
}

func (i Iblt) MarshalBinary() ([]byte, error) {
	data := make([]byte, i.numBuckets()*bucketBytes)
	for idx, b := range i.Buckets {
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
	i.Hc = ibltHc
	i.Hk = ibltHk
	i.K = ibltK
	i.Buckets = makeBuckets(numBuckets)
	for j := 0; j < i.numBuckets(); j++ {
		err := i.Buckets[j].UnmarshalBinary(buf.Next(bucketBytes))
		if err != nil {
			return fmt.Errorf("unmarshalling failed - %w", err)
		}
	}
	return nil
}

// bucket
type bucket struct {
	// Count is signed to allow for negative counts after subtraction
	Count   int32           `json:"count"`    // #1
	HashSum uint64          `json:"hash_sum"` // #2
	KeySum  hash.SHA256Hash `json:"key_sum"`  // #3
}

func (b *bucket) insert(key hash.SHA256Hash, hash uint64) {
	b.Count++
	b.update(key, hash)
}

func (b *bucket) delete(key hash.SHA256Hash, hash uint64) {
	b.Count--
	b.update(key, hash)
}

func (b *bucket) add(o *bucket) {
	b.Count += o.Count
	b.update(o.KeySum, o.HashSum)
}

func (b *bucket) subtract(o *bucket) {
	b.Count -= o.Count
	b.update(o.KeySum, o.HashSum)
}

func (b *bucket) update(key hash.SHA256Hash, hash uint64) {
	xor(&b.KeySum, b.KeySum, key)
	b.HashSum ^= hash
}

func (b bucket) clone() *bucket {
	return &b
}

func (b bucket) isEmpty() bool {
	return b.equals(*new(bucket))
}

func (b bucket) equals(o bucket) bool {
	return b.Count == o.Count && b.HashSum == o.HashSum && b.KeySum == o.KeySum
}

func (b bucket) String() string {
	return fmt.Sprintf("{Count:%d KeySum:%s HashSum:%d}", b.Count, b.KeySum, b.HashSum)
}

func (b bucket) MarshalBinary() ([]byte, error) {
	bs := make([]byte, bucketBytes)
	byteOrder().PutUint32(bs, uint32(b.Count)) // #1
	byteOrder().PutUint64(bs[4:], b.HashSum)   // #2
	copy(bs[12:], b.KeySum.Clone().Slice())    // #3
	return bs, nil
}

func (b *bucket) UnmarshalBinary(data []byte) error {
	if len(data) != bucketBytes {
		return errors.New("invalid data length")
	}
	buf := bytes.NewBuffer(data)
	b.Count = int32(byteOrder().Uint32(buf.Next(4)))         // #1
	b.HashSum = byteOrder().Uint64(buf.Next(8))              // #2
	b.KeySum = hash.FromSlice(buf.Next(hash.SHA256HashSize)) // #3
	return nil
}

func byteOrder() binary.ByteOrder {
	return binary.LittleEndian
}
