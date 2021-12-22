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

		ldproof := LDProof{
			input: map[string]interface{}{
				"@context": map[string]interface{}{"title": "https://schema.org#title"},
				"title":    "This is the document title",
			},

			options: ProofOptions{
				KID:     "nuts:did:123#key-1",
				Created: time.Date(2021, 12, 22, 15, 21, 12, 0, time.FixedZone("Amsterdam", int(2*time.Hour.Seconds()))),
				Domain:  &domain,
				Nonce:   &nonce,
			},
		}

		assert.NoError(t, ldproof.Canonicalize(), "expected canonicalization to succeed")
		assert.NoError(t, ldproof.CreateToBeSigned(), "expected ToBeSigned creation to succeed")
	})
}
