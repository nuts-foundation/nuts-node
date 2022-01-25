/*
 * Copyright (C) 2021 Nuts community
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

// IsSet checks whether the bit at index `index` was set
func (set *BitSet) IsSet(index int64) bool {
	return set.bits[index].Load() != nil
}

// Set sets the bit at index `index`
func (set *BitSet) Set(index int64) {
	set.bits[index].Store(true)
}

// Len returns the size of the bitSet
func (set *BitSet) Len() int {
	return len(set.bits)
}
