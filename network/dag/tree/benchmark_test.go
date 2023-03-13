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
	"fmt"
	"math"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

func BenchmarkTree(b *testing.B) {
	b.Run("IBLT", func(b *testing.B) {
		BenchProto(b, NewIblt(numTestBuckets))
	})

	b.Run("Xor", func(b *testing.B) {
		BenchProto(b, NewXor())
	})
}

func BenchProto(b *testing.B, proto Data) {
	b.Run("tree.Load()", func(b *testing.B) { BenchTree_Load(b, proto) })
	b.Run("Data", func(b *testing.B) { BenchData(b, proto) })
}

func BenchTree_Load(b *testing.B, proto Data) {
	leafSize := uint32(512)
	maxDepth := 16
	tree := New(proto, leafSize)
	benchTree := New(proto, leafSize)
	nextLeaf := uint32(0)

	for d := 0; d < maxDepth; d++ {
		numLeaves := uint32(math.Pow(2, float64(d)))
		dirties := map[uint32][]byte{}
		for i := nextLeaf; i < numLeaves; i++ {
			tree.Insert(hash.RandomHash(), i*leafSize)
			nextLeaf++
		}
		dirties, _ = tree.Updates() // tree.ResetUpdates() is never called, so dirties contains all leaves.

		b.Run(fmt.Sprintf("Depth=%d Transactions=%d", d, numLeaves*leafSize), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = benchTree.Load(dirties)
			}
		})
	}
}

func BenchData(b *testing.B, proto Data) {

	b.Run("New()", func(b *testing.B) {
		var data Data
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data = proto.New()
		}
		_ = data
	})

	b.Run("Clone()", func(b *testing.B) {
		data, _ := dataWithRandomHashes(proto, 128)
		var clone Data
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			clone = data.Clone()
		}
		_ = clone
	})

	b.Run("Insert()", func(b *testing.B) {
		data, _ := dataWithRandomHashes(proto, 128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data.Insert(hash.RandomHash())
		}
	})

	b.Run("Delete()", func(b *testing.B) {
		data, _ := dataWithRandomHashes(proto, 128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data.Delete(hash.RandomHash())
		}
	})

	b.Run("Add()", func(b *testing.B) {
		data1, _ := dataWithRandomHashes(proto, 128)
		data2, _ := dataWithRandomHashes(proto, 128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = data1.Add(data2)
		}
	})

	b.Run("Subtract()", func(b *testing.B) {
		data1, _ := dataWithRandomHashes(proto, 128)
		data2, _ := dataWithRandomHashes(proto, 128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = data1.Subtract(data2)
		}
	})

	b.Run("Empty()", func(b *testing.B) {
		b.Run("true", func(b *testing.B) {
			data := proto.New()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = data.Empty()
			}
		})
		b.Run("false", func(b *testing.B) {
			data, _ := dataWithRandomHashes(proto, 128)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = data.Empty()
			}
		})
	})

	b.Run("MarshalBinary()", func(b *testing.B) {
		data, _ := dataWithRandomHashes(proto, 128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = data.MarshalBinary()
		}
	})

	b.Run("UnmarshalBinary()", func(b *testing.B) {
		data, _ := dataWithRandomHashes(proto, 128)
		bytes, _ := data.MarshalBinary()
		data = data.New()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = data.UnmarshalBinary(bytes)
		}
	})
}

func dataWithRandomHashes(proto Data, numHashes int) (Data, map[hash.SHA256Hash]struct{}) {
	data := proto.New()
	hashes := make(map[hash.SHA256Hash]struct{}, numHashes)
	for i := 0; i < numHashes; i++ {
		ref := hash.RandomHash()
		data.Insert(ref)
		hashes[ref] = struct{}{}
	}
	return data, hashes
}
