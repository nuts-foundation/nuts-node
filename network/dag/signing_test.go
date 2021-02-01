package dag

import (
	"crypto/sha1"
	"encoding/base32"
	"github.com/nuts-foundation/nuts-node/crypto"
	"testing"
	"time"

	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestDocumentSigner(t *testing.T) {
	payloadHash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	key := generateKey()
	kidAsArray := sha1.Sum(key.X.Bytes())
	kid := base32.HexEncoding.EncodeToString(kidAsArray[:])
	prev1, _ := hash2.ParseHex("3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986")
	prev2, _ := hash2.ParseHex("b3f2c3c396da1a949d214e4c2fe0fc9fb5f2a68ff1860df4ef10c9835e62e7c1")
	expectedPrevs := []hash2.SHA256Hash{prev1, prev2}
	contentType := "foo/bar"
	moment := time.Date(2020, 10, 23, 13, 0, 0, 0, time.FixedZone("test", 1))
	t.Run("ok - attach key", func(t *testing.T) {
		doc, err := NewDocument(payloadHash, contentType, expectedPrevs)
		if !assert.NoError(t, err) {
			return
		}

		signer := crypto.NewTestSigner()
		signedDoc, err := NewAttachedJWKDocumentSigner(signer, kid, &crypto.StaticKeyResolver{Key: key.Public()}).Sign(doc, moment)
		if !assert.NoError(t, err) {
			return
		}
		// JWS headers
		assert.Equal(t, contentType, signedDoc.PayloadType())
		assert.Empty(t, signedDoc.SigningKeyID())
		// Custom headers
		assert.Equal(t, "2020-10-23 12:59:59 +0000 UTC", signedDoc.SigningTime().String())
		assert.Equal(t, Version(1), signedDoc.Version())
		prevs := signedDoc.Previous()
		assert.Len(t, prevs, 2, "expected 2 prevs")
		assert.Equal(t, prev1, prevs[0])
		assert.Equal(t, prev2, prevs[1])
		// Resulting doc
		assert.NotEmpty(t, signedDoc.Data())
		assert.False(t, signedDoc.Ref().Empty())
		assert.Equal(t, time.UTC, signedDoc.SigningTime().Location())
	})
	t.Run("ok - with kid", func(t *testing.T) {
		doc, err := NewDocument(payloadHash, contentType, expectedPrevs)
		if !assert.NoError(t, err) {
			return
		}

		signer := crypto.NewTestSigner()
		signedDoc, err := NewDocumentSigner(signer, kid).Sign(doc, moment)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, kid, signedDoc.SigningKeyID())
		assert.Nil(t, signedDoc.SigningKey())
		assert.NotEmpty(t, signedDoc.Data())
	})
	t.Run("signing time is zero", func(t *testing.T) {
		doc, _ := NewDocument(payloadHash, contentType, expectedPrevs)
		signedDocument, err := NewDocumentSigner(crypto.NewTestSigner(), kid).Sign(doc, time.Time{})
		assert.Empty(t, signedDocument)
		assert.EqualError(t, err, "signing time is zero")
	})
	t.Run("already signed", func(t *testing.T) {
		doc, _ := NewDocument(payloadHash, contentType, expectedPrevs)
		signer := NewDocumentSigner(crypto.NewTestSigner(), kid)
		signedDocument, _ := signer.Sign(doc, time.Now())
		signedDocument2, err := signer.Sign(signedDocument, time.Now())
		assert.Nil(t, signedDocument2)
		assert.EqualError(t, err, "document is already signed")
	})
}
