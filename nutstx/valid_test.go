package nutstx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/stream"
)

func BenchmarkValid(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// single sample
	var content = []byte{0} // arbitrary transaction data
	const token = "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsic2lndCIsInZlciIsInByZXZzIiwibGMiXSwiY3R5IjoiYXBwbGljYXRpb24vZGlkK2pzb24iLCJraWQiOiJ0ZXN0LWtleSIsImxjIjowLCJwcmV2cyI6W10sInNpZ3QiOjE2Njg2OTYyMDAsInZlciI6Mn0.NmUzNDBiOWNmZmIzN2E5ODljYTU0NGU2YmI3ODBhMmM3ODkwMWQzZmIzMzczODc2ODUxMWEzMDYxN2FmYTAxZA.OBBnvRxerJEL-Qaerxef3I4P62avq9ihYnSIfHd-SPLVUVhmMQyg8pgxLw8s5FfZchsQ4VaXbuT7eOwtanZBRw"
	key := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}
	key.X.SetString("63034895643221788472610173124010092768542486664520124763050582067459299772736", 10)
	key.Y.SetString("67599489229846423951267283483643514095096616923146952670388600905714246400878", 10)
	signTime := time.Date(2022, 11, 17, 14, 43, 20, 0, time.UTC)

	// stub aggregate set lookup
	aggs := NewAggregateSet()
	aggs.SignatureAggregate.perKeyID["test-key"] = key
	liveSince := func(ctx context.Context, notBefore time.Time) (*AggregateSet, time.Time, error) {
		if err := ctx.Err(); err != nil {
			return nil, time.Time{}, err
		}
		if !notBefore.Equal(signTime) {
			b.Errorf("LiveSince invoked with notBefore %s, want %s from token %s", notBefore, signTime, token)
		}
		return aggs, time.Now(), nil
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		err := ValidEvent(ctx, stream.Event{JWS: token, Content: content}, liveSince)
		if err != nil {
			b.Fatal(err)
		}
	}
}
