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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/twmb/murmur3"
)

const (
	ibltHc      = uint64(0)
	ibltHk      = uint32(1)
	ibltK       = uint8(6)
	bucketBytes = 44 // = int32 + uint64 + hash.SHA256HashSize
)

// ErrDecodeNotPossible is returned when the Iblt cannot be decoded.
var (
	ErrDecodeNotPossible = errors.New("decode failed")
	ErrDecodeLoop        = errors.New("decode loop detected")
)

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
	buckets []bucket
}

// NewIblt returns an *Iblt with default settings and specified number of buckets. numBuckets must be >= Iblt.k
func NewIblt(numBuckets int) *Iblt {
	if numBuckets < int(ibltK) {
		numBuckets = int(ibltK)
	}
	return &Iblt{
		buckets: make([]bucket, numBuckets),
		hc:      ibltHc,
		hk:      ibltHk,
		k:       ibltK,
	}
}

func (i *Iblt) New() Data {
	return NewIblt(i.numBuckets())
}

func (i *Iblt) Clone() Data {
	clone := &Iblt{
		hc:      i.hc,
		hk:      i.hk,
		k:       i.k,
		buckets: make([]bucket, i.numBuckets()),
	}
	copy(clone.buckets, i.buckets)
	return clone
}

func (i *Iblt) Insert(ref hash.SHA256Hash) {
	keyHash := i.hashKey(ref)
	for _, h := range i.bucketIndices(keyHash) {
		i.buckets[h].insert(ref, keyHash)
	}
}

func (i *Iblt) Delete(key hash.SHA256Hash) {
	keyHash := i.hashKey(key)
	for _, h := range i.bucketIndices(keyHash) {
		i.buckets[h].delete(key, keyHash)
	}
}

func (i *Iblt) Add(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx := range i.buckets {
		i.buckets[idx].add(&o.buckets[idx])
	}
	return nil
}

func (i *Iblt) Subtract(other Data) error {
	o, err := i.validate(other)
	if err != nil {
		return err
	}
	for idx := range i.buckets {
		i.buckets[idx].subtract(&o.buckets[idx])
	}
	return nil
}

// validate returns other as an *Iblt if it is compatible with self, or an error if not.
func (i *Iblt) validate(other Data) (*Iblt, error) {
	// validate datatype
	o, ok := other.(*Iblt)
	if !ok {
		return nil, fmt.Errorf("other invalid - expected type %T, got %T", i, other)
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
	pures := map[hash.SHA256Hash]bool{}

	for {
		updated := false

		// peel off pures (count == ±1)
		for idx := range i.buckets {
			if (i.buckets[idx].count == 1 || i.buckets[idx].count == -1) && i.hashKey(i.buckets[idx].keySum) == i.buckets[idx].hashSum {
				txRef := i.buckets[idx].keySum
				if pures[txRef] {
					// Decode gets stuck in a loop when the b.keySum is not exactly ±1 times in all buckets with indices i.bucketIndices(b.hashSum)
					// this can occur when two Iblt are subtracted that use different methods for assigning buckets
					err = ErrDecodeLoop
					return
				}
				pures[txRef] = true

				if i.buckets[idx].count == 1 {
					remaining = append(remaining, txRef)
					i.Delete(txRef)
				} else { // b.count == -1
					missing = append(missing, txRef)
					i.Insert(txRef)
				}
				updated = true
			}
		}

		// if no pures exist, the iblt is empty or cannot be decoded
		if !updated {
			if !i.Empty() {
				err = ErrDecodeNotPossible
			}
			break
		}
	}

	return remaining, missing, err
}

func (i *Iblt) Empty() bool {
	for idx := range i.buckets {
		if !i.buckets[idx].isEmpty() {
			return false
		}
	}
	return true
}

func (i *Iblt) numBuckets() int {
	return len(i.buckets)
}

func (i *Iblt) bucketIndices(hash uint64) []uint32 {
	bucketUsed := make(map[uint32]bool, i.k)
	indices := make([]uint32, 0, i.hk)
	hashKeyBytes, nextBytes := make([]byte, 8), make([]byte, 4)
	byteOrder.PutUint64(hashKeyBytes, hash)
	next := murmur3.SeedSum32(i.hk, hashKeyBytes)
	for len(indices) < int(i.k) {
		bucketID := next % uint32(i.numBuckets())
		if !bucketUsed[bucketID] {
			indices = append(indices, bucketID)
			bucketUsed[bucketID] = true
		}
		byteOrder.PutUint32(nextBytes, next)
		next = murmur3.SeedSum32(i.hk, nextBytes)
	}
	return indices
}

func (i *Iblt) hashKey(key hash.SHA256Hash) uint64 {
	return murmur3.SeedSum64(i.hc, key.Slice())
}

func (i *Iblt) MarshalBinary() ([]byte, error) {
	data := make([]byte, i.numBuckets()*bucketBytes)
	for idx := range i.buckets {
		bs, err := i.buckets[idx].MarshalBinary()
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
	i.buckets = make([]bucket, numBuckets)
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
	b.keySum = b.keySum.Xor(key)
	b.hashSum ^= hash
}

func (b *bucket) isEmpty() bool {
	return b.equals(new(bucket))
}

func (b *bucket) equals(o *bucket) bool {
	return *b == *o
}

func (b *bucket) String() string {
	return fmt.Sprintf("{count:%d keySum:%s hashSum:%d}", b.count, b.keySum, b.hashSum)
}

func (b *bucket) MarshalBinary() ([]byte, error) {
	bs := [bucketBytes]byte{}
	byteOrder.PutUint32(bs[0:], uint32(b.count)) // #1
	byteOrder.PutUint64(bs[4:], b.hashSum)       // #2
	copy(bs[12:], b.keySum.Clone().Slice())      // #3
	return bs[:], nil
}

func (b *bucket) UnmarshalBinary(data []byte) error {
	if len(data) != bucketBytes {
		return errors.New("invalid data length")
	}
	d := (*[bucketBytes]byte)(data)
	b.count = int32(byteOrder.Uint32(d[:4])) // #1
	b.hashSum = byteOrder.Uint64(d[4:12])    // #2
	keySum := (*hash.SHA256Hash)(d[12:])
	b.keySum = *keySum // #3
	return nil
}

// byteOrder returns the binary.ByteOrder described in the specs.
// This guarantees Iblt generation is platform independent and allows decentralized comparison.
var byteOrder = binary.LittleEndian
