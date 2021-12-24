package proof

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestLDProof_CreateToBeSigned(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		domain := "kik-v"
		nonce := "random-nonce"

		input := map[string]interface{}{
			"@context": map[string]interface{}{"title": "https://schema.org#title"},
			"title":    "This is the document title",
		}
		ldproof := ldProofBuilder{
			options: ProofOptions{
				KID:     "nuts:did:123#key-1",
				Created: time.Date(2021, 12, 22, 15, 21, 12, 0, time.FixedZone("Amsterdam", int(2*time.Hour.Seconds()))),
				Domain:  &domain,
				Nonce:   &nonce,
			},
		}

		assert.NoError(t, ldproof.canonicalize(input), "expected canonicalization to succeed")
		assert.NoError(t, ldproof.CreateToBeSigned(), "expected ToBeSigned creation to succeed")
	})
}

func TestLDProof_Copy(t *testing.T) {
	t.Run("ok - copies the object", func(t *testing.T) {
		type testStruct struct {
			Key *string
		}
		testValue := "value"
		testInput := &testStruct{Key: &testValue}
		ldproof := ldProofBuilder{input: testInput}
		copyResult, err := ldproof.copy()

		assert.IsType(t, &testStruct{}, copyResult)
		testCopy := copyResult.(*testStruct)

		assert.NoError(t, err)
		assert.Equal(t, "value", *testCopy.Key, "the copy should contain the Keys value")
		*testInput.Key = "newValue"
		assert.Equal(t, "value", *testCopy.Key, "the copy should not change with the original")
	})
}
