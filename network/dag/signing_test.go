package dag

import (
	"crypto"
	"crypto/sha1"
	"encoding/base32"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/core"
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

		signer := &trackingJWSSigner{}
		signedDoc, err := NewAttachedJWKDocumentSigner(signer, kid, &simpleKeyResolver{key: key}).Sign(doc, moment)
		if !assert.NoError(t, err) {
			return
		}
		// JWS headers
		assert.Equal(t, contentType, signer.headers[jws.ContentTypeKey])
		assert.Empty(t, signer.headers[jws.KeyIDKey])
		// Custom headers
		assert.Equal(t, int64(1603457999), signer.headers[signingTimeHeader].(int64))
		assert.Equal(t, 1, int(signer.headers[versionHeader].(Version)))
		prevs := signer.headers[previousHeader]
		assert.Len(t, prevs, 2, "expected 2 prevs")
		assert.Equal(t, prev1.String(), prevs.([]string)[0])
		assert.Equal(t, prev2.String(), prevs.([]string)[1])
		// Resulting doc
		assert.Equal(t, "fine JWS", string(signedDoc.Data()))
		assert.False(t, signedDoc.Ref().Empty())
		assert.Equal(t, time.UTC, signedDoc.SigningTime().Location())
	})
	t.Run("ok - with kid", func(t *testing.T) {
		doc, err := NewDocument(payloadHash, contentType, expectedPrevs)
		if !assert.NoError(t, err) {
			return
		}

		signer := &trackingJWSSigner{}
		signedDoc, err := NewDocumentSigner(signer, kid).Sign(doc, moment)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, kid, signer.headers[jws.KeyIDKey])
		assert.Nil(t, signer.headers[jws.JWKKey])
		assert.Equal(t, "fine JWS", string(signedDoc.Data()))
	})
}

type simpleKeyResolver struct {
	key crypto.PublicKey
}

func (s simpleKeyResolver) GetPublicKey(_ string, _ time.Time) (crypto.PublicKey, error) {
	return s.key, nil
}

func (s simpleKeyResolver) SavePublicKey(kid string, publicKey crypto.PublicKey, period core.Period) error {
	panic("implement me")
}

type trackingJWSSigner struct {
	headers map[string]interface{}
	payload []byte
	kid     string
}

func (t *trackingJWSSigner) SignJWS(payload []byte, protectedHeaders map[string]interface{}, kid string) (string, error) {
	t.payload = payload
	t.headers = protectedHeaders
	t.kid = kid
	return "fine JWS", nil
}
