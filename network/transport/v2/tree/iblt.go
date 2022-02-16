package tree

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/spaolacci/murmur3"
)

const (
	ibltNumBuckets = 1024
)

/*
Implementation of an Invertible Bloom Filter, which is the special case of an IBLT where the key-value pair consist of a key-hash(key) pair.
The hash(key) value ensures correct decoding after subtraction of two IBLTs.
Goodrich, Michael T., and Michael Mitzenmacher. "Invertible bloom lookup tables." http://arxiv.org/pdf/1101.2245
Eppstein, David, et al. "What's the difference?: efficient set reconciliation without prior context." http://conferences.sigcomm.org/sigcomm/2011/papers/sigcomm/p218.pdf
*/

type Iblt struct {
	Buckets []*bucket `json:"buckets"`
	Hc      uint32    `json:"Hc"`
	Hk      uint32    `json:"Hk"`
	K       int       `json:"K"`
}

func NewIblt(numBuckets int) *Iblt {
	buckets := make([]*bucket, numBuckets)
	for i := 0; i < numBuckets; i++ {
		buckets[i] = new(bucket)
	}
	return &Iblt{
		Buckets: buckets,
		Hc:      uint32(0),
		Hk:      uint32(1),
		K:       6,
	}
}

func (i *Iblt) New() Data {
	return NewIblt(len(i.Buckets))
}

func (i *Iblt) Clone() Data {
	return i.clone()
}

func (i *Iblt) Insert(ref hash.SHA256Hash) error {
	i.Add(ref)
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

func (i Iblt) clone() *Iblt {
	tmpBuckets := make([]*bucket, len(i.Buckets))
	for idx, b := range i.Buckets {
		tmpBuckets[idx] = b.clone()
	}
	i.Buckets = tmpBuckets
	return &i
}

func (i *Iblt) Add(key hash.SHA256Hash) {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].add(key, keyHash)
	}
}

func (i *Iblt) Delete(key hash.SHA256Hash) {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.Buckets[h].delete(key, keyHash)
	}
}

func (i *Iblt) subtract(other *Iblt) error {
	if err := i.validateSubtrahend(other); err != nil {
		return fmt.Errorf("subtraction failed: %w", err)
	}
	for idx, b := range i.Buckets {
		b.subtract(other.Buckets[idx])
	}
	return nil
}

func (i *Iblt) validateSubtrahend(o *Iblt) error {
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

		// for each pure (count == +1 or -1), if hashSum = h(key) -> Add(count == -1)/Delete(count == 1) key
		for _, b := range i.Buckets {
			if (b.Count == 1 || b.Count == -1) && i.hashKey(b.KeySum) == b.HashSum {
				if b.Count == 1 {
					remaining = append(remaining, b.KeySum)
					i.Delete(b.KeySum)
				} else { // b.count == -1
					missing = append(missing, b.KeySum)
					i.Add(b.KeySum)
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

func (i *Iblt) bucketIndices(hash uint64) []uint64 {
	bucketUsed := make(map[uint64]bool, i.K)
	var indices []uint64
	next := xorshift64(hash)
	for len(indices) < i.K {
		bucketId := next % uint64(len(i.Buckets))
		if !bucketUsed[bucketId] {
			indices = append(indices, bucketId)
			bucketUsed[bucketId] = true
		}
		next = xorshift64(next)
	}
	return indices
}

func (i *Iblt) hashKey(key hash.SHA256Hash) uint64 {
	return murmur3.Sum64WithSeed(key[:], i.Hc)
}

// bucket
type bucket struct {
	// Count is signed to allow for negative counts after subtraction
	Count   int             `json:"count"`
	KeySum  hash.SHA256Hash `json:"key_sum"`
	HashSum uint64          `json:"hash_sum"`
}

func (b *bucket) add(key hash.SHA256Hash, hash uint64) {
	b.Count++
	b.update(key, hash)
}

func (b *bucket) delete(key hash.SHA256Hash, hash uint64) {
	b.Count--
	b.update(key, hash)
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

// xorshift64 is am RNG form the xorshift family with period 2^64-1.
func xorshift64(s uint64) uint64 {
	if s == 0 { // xorshift64(0) == 0
		s++
	}
	s ^= s << 13
	s ^= s >> 7
	s ^= s << 17
	return s
}
