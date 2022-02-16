package tree

import (
	"encoding/json"
	"fmt"
	"github.com/spaolacci/murmur3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewIblt(t *testing.T) {
	iblt1 := NewIblt(ibltNumBuckets)
	iblt2 := NewIblt(ibltNumBuckets)

	iblt1.Add(generateTxRef())
	iblt2.Add(generateTxRef())

	iblt1Clone := iblt1.clone()
	fmt.Printf("%+v\n", iblt1Clone)

	for idx, b := range iblt1.Buckets {
		if !b.isEmpty() {
			println("not empty")
			fmt.Printf("%+v\n", b)
			fmt.Printf("%+v\n", iblt1Clone.Buckets[idx])
			assert.Equal(t, b, iblt1Clone.Buckets[idx])
		}
	}

	err := iblt1.subtract(iblt2)
	assert.NoError(t, err)

	remaining, missing, err := iblt1.Decode()
	if err != nil {
		return
	}
	assert.Equal(t, 1, len(remaining))
	assert.Equal(t, 1, len(missing))
	println(remaining)
	println(missing)
}

func BenchmarkIblt_Insert(b *testing.B) {
	tr := New(NewIblt(ibltNumBuckets), leafSize)
	for i := 0; i < 128; i++ {
		_ = tr.Insert(generateTxRef(), uint32(i)*leafSize)
	}

	for i := 0; i < b.N; i++ {
		jsonData, _ := json.Marshal(tr)
		tr = &Tree{}
		_ = json.Unmarshal(jsonData, tr)
	}
}

func TestIblt_Clone(t *testing.T) {
	tr := New(NewIblt(ibltNumBuckets), leafSize)

	for i := uint32(0); i < 200_000; i++ {
		tr.Insert(generateTxRef(), i)
	}
	fmt.Printf("%+v\n", tr)
	jsonData, err := json.Marshal(tr)
	//println(string(jsonData))
	assert.NoError(t, err)
	fmt.Printf("%d\n", len(jsonData))
}

func TestBucket_clone(t *testing.T) {
	b := new(bucket)
	h := generateTxRef()
	b.add(h, murmur3.Sum64WithSeed(h[:], 0))

	c := b.clone()

	fmt.Printf("%+v\n", b)
	fmt.Printf("%+v\n", c)

	h2 := generateTxRef()
	b.add(h2, murmur3.Sum64WithSeed(h2[:], 0))

	fmt.Printf("%+v\n", b)
	fmt.Printf("%+v\n", c)

}

func TestIblt_Clone2(t *testing.T) {
	iblt := NewIblt(6)
	fmt.Printf("%+v\n", iblt)
	ibltClone := iblt.clone()
	iblt.Add(generateTxRef())
	ibltClone2 := iblt.clone()
	fmt.Printf("%+v\n", iblt)
	fmt.Printf("%+v\n", ibltClone)
	fmt.Printf("%+v\n", ibltClone2)

	jsonData, _ := json.Marshal(iblt)
	println(string(jsonData))
}
