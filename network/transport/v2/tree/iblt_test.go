package tree

import (
	"encoding/json"
	"testing"
)

func BenchmarkIblt_JSONMarshal(b *testing.B) {
	iblt := getIbltWithRandomData(128)
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(iblt)
	}
}

func BenchmarkIblt_JSONUnmarshal(b *testing.B) {
	iblt := getIbltWithRandomData(128)
	jsonData, _ := json.Marshal(iblt)
	for i := 0; i < b.N; i++ {
		iblt = &Iblt{}
		_ = json.Unmarshal(jsonData, iblt)
	}
}

func BenchmarkIblt_BinaryMarshal(b *testing.B) {
	iblt := getIbltWithRandomData(128)
	for i := 0; i < b.N; i++ {
		_, _ = iblt.MarshalBinary()
	}
}

func BenchmarkIblt_BinaryUnmarshal(b *testing.B) {
	iblt := getIbltWithRandomData(128)
	bytes, _ := iblt.MarshalBinary()
	for i := 0; i < b.N; i++ {
		iblt = &Iblt{}
		_ = iblt.UnmarshalBinary(bytes)
	}
}

func getIbltWithRandomData(nHashes int) *Iblt {
	iblt := NewIblt(ibltNumBuckets)
	for i := 0; i < nHashes; i++ {
		_ = iblt.Insert(generateTxRef())
	}
	return iblt
}
