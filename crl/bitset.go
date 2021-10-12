package crl

import "sync/atomic"

// BitSet implements a fixed-length atomic bitset backed by a slice of booleans
type BitSet struct {
	bits []atomic.Value
}

// NewBitSet create a fixed-length bitSe
func NewBitSet(size int) *BitSet {
	return &BitSet{bits: make([]atomic.Value, size)}
}

// IsSet checks wether the bit at index `index` was set
func (set *BitSet) IsSet(index int) bool {
	return set.bits[index].Load() != nil
}

// Set sets the bit at index `index`
func (set *BitSet) Set(index int) {
	set.bits[index].Store(true)
}

// Len returns the size of the bitSet
func (set *BitSet) Len() int {
	return len(set.bits)
}
