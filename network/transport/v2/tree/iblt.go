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
	ibltK          = 6
	bucketBytes    = 44 // = int32 + uint64 + hash.SHA256HashSize
)

/*
Implementation of an Invertible Bloom Filter, which is the special case of an IBLT where the key-value pair consist of a key-hash(key) pair.
The hash(key) value ensures correct decoding after subtraction of two IBLTs.
Goodrich, Michael T., and Michael Mitzenmacher. "Invertible bloom lookup tables." http://arxiv.org/pdf/1101.2245
Eppstein, David, et al. "What's the difference?: efficient set reconciliation without prior context." http://conferences.sigcomm.org/sigcomm/2011/papers/sigcomm/p218.pdf
*/

type Iblt struct {
	Hc      uint32    `json:"Hc"`      // #1
	Hk      uint32    `json:"Hk"`      // #2
	K       uint8     `json:"K"`       // #3
	Buckets []*bucket `json:"buckets"` // #4
}

func NewIblt(numBuckets int) *Iblt {
	return &Iblt{
		Buckets: makeBuckets(numBuckets),
		Hc:      ibltHc,
		Hk:      ibltHk,
		K:       ibltK,
	}
}

func makeBuckets(numBuckets int) []*bucket {
	buckets := make([]*bucket, numBuckets)
	for i := 0; i < numBuckets; i++ {
		buckets[i] = new(bucket)
	}
	return buckets
}

func (i *Iblt) New() Data {
	return NewIblt(len(i.Buckets))
}

func (i *Iblt) Clone() Data {
	return i.clone()
}

func (i *Iblt) Insert(ref hash.SHA256Hash) error {
	keyHash := i.hashKey(ref)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].insert(ref, keyHash)
	}
	return nil
}

func (i *Iblt) Subtract(other Data) error {
	switch o := other.(type) {
	case *Iblt:
		return i.subtract(o)
	default:
		return fmt.Errorf("subtraction failed - expected type %T, got %T", i, o)
	}
}

func (i *Iblt) subtract(other *Iblt) error {
	if err := i.matches(other); err != nil {
		return fmt.Errorf("subtraction failed: %w", err)
	}
	for idx, b := range i.Buckets {
		b.subtract(other.Buckets[idx])
	}
	return nil
}

func (i *Iblt) Add(other Data) error {
	switch o := other.(type) {
	case *Iblt:
		return i.subtract(o)
	default:
		return fmt.Errorf("addition failed - expected type %T, got %T", i, o)
	}
}

func (i *Iblt) add(other *Iblt) error {
	if err := i.matches(other); err != nil {
		return fmt.Errorf("addition failed: %w", err)
	}
	for idx, b := range i.Buckets {
		b.add(other.Buckets[idx])
	}
	return nil
}

func (i Iblt) clone() *Iblt {
	tmpBuckets := make([]*bucket, len(i.Buckets))
	for idx, b := range i.Buckets {
		tmpBuckets[idx] = b.clone()
	}
	i.Buckets = tmpBuckets
	return &i
}

func (i *Iblt) Delete(key hash.SHA256Hash) {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].delete(key, keyHash)
	}
}

func (i *Iblt) matches(o *Iblt) error {
	if len(i.Buckets) != len(o.Buckets) {
		return fmt.Errorf("number of Buckets do not match, expected (%d) got (%d)", len(i.Buckets), len(o.Buckets))
	}
	if i.Hc != o.Hc {
		return fmt.Errorf("Hc do not match, expected (%d) got (%d)", i.Hc, o.Hc)
	}
	if i.Hk != o.Hk {
		return fmt.Errorf("Hk do not match, expected (%d) got (%d)", i.Hk, o.Hk)
	}
	if i.K != o.K {
		return fmt.Errorf("unequal number of K, expected (%d) got (%d)", i.K, o.K)
	}
	return nil
}

func (i *Iblt) Decode() (remaining []hash.SHA256Hash, missing []hash.SHA256Hash, err error) {
	for {
		updated := false

		// for each pure (count == +1 or -1), if hashSum = h(key) -> insert(count == -1)/Delete(count == 1) key
		for _, b := range i.Buckets {
			if (b.Count == 1 || b.Count == -1) && i.hashKey(b.KeySum) == b.HashSum {
				if b.Count == 1 {
					remaining = append(remaining, b.KeySum)
					i.Delete(b.KeySum)
				} else { // b.count == -1
					missing = append(missing, b.KeySum)
					err = i.Insert(b.KeySum)
					if err != nil {
						return nil, nil, err
					}
				}
				updated = true
			}
		}

		// if no pures exist, the Iblt is empty or cannot be decoded
		if !updated {
			for _, b := range i.Buckets {
				if !b.isEmpty() {
					return remaining, missing, errors.New("decode failed")
				}
			}
			return remaining, missing, nil
		}
	}
}

func (i *Iblt) bucketIndices(hash uint64) []uint32 {
	bucketUsed := make(map[uint32]bool, i.K)
	var indices []uint32
	hashBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(hashBytes, hash)
	next := murmur3.Sum32WithSeed(hashBytes, i.Hk)
	for len(indices) < int(i.K) {
		bucketId := next % uint32(len(i.Buckets))
		if !bucketUsed[bucketId] {
			indices = append(indices, bucketId)
			bucketUsed[bucketId] = true
		}
		binary.LittleEndian.PutUint32(hashBytes, next)
		next = murmur3.Sum32WithSeed(hashBytes[:4], i.Hk)
	}
	return indices
}

func (i *Iblt) hashKey(key hash.SHA256Hash) uint64 {
	return murmur3.Sum64WithSeed(key[:], i.Hc)
}

func (i Iblt) MarshalBinary() ([]byte, error) {
	data := make([]byte, ibltNumBuckets*bucketBytes)
	p := 0
	for idx, b := range i.Buckets {
		bs, err := b.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("bucket %d: %w", idx, err)
		}
		copy(data[p:], bs) // #4
		p += bucketBytes
	}
	return data, nil
}

func (i *Iblt) UnmarshalBinary(data []byte) error {
	if len(data) != ibltNumBuckets*bucketBytes {
		return errors.New("invalid data length")
	}
	buf := bytes.NewBuffer(data)
	i.Hc = ibltHc
	i.Hk = ibltHk
	i.K = ibltK
	i.Buckets = makeBuckets(ibltNumBuckets)
	for j := 0; j < len(i.Buckets); j++ {
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
	return b.Count == 0 && b.HashSum == 0 && b.KeySum == hash.EmptyHash()
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
	b.Count = int32(byteOrder().Uint32(buf.Next(4))) // #1
	b.HashSum = byteOrder().Uint64(buf.Next(8))      // #2
	b.KeySum = hash.FromSlice(buf.Next(32))          // #3
	return nil
}

//
func byteOrder() binary.ByteOrder {
	return binary.LittleEndian
}
