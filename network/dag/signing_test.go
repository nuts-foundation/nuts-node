package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
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
		signedDoc, err := NewAttachedJWKDocumentSigner(signer, kid, &crypto.StaticKeyResolver{Key: key}).Sign(doc, moment)
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
	t.Run("resolver returns public key", func(t *testing.T) {
		doc, _ := NewDocument(payloadHash, contentType, expectedPrevs)
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer := &trackingJWSSigner{}
		_, err := NewAttachedJWKDocumentSigner(signer, kid, crypto.StaticKeyResolver{Key: privateKey}).Sign(doc, moment)
		assert.NoError(t, err)
		assert.IsType(t, jwk.NewECDSAPublicKey(), signer.headers[jws.JWKKey])
	})
}

func TestDocumentSignatureVerifier(t *testing.T) {
	t.Run("embedded JWK, sign -> verify", func(t *testing.T) {
		err := NewDocumentSignatureVerifier(nil).Verify(CreateTestDocumentWithJWK(1))
		assert.NoError(t, err)
	})
	t.Run("embedded JWK, sign -> marshal -> unmarshal -> verify", func(t *testing.T) {
		expected, _ := ParseDocument(CreateTestDocumentWithJWK(1).Data())
		err := NewDocumentSignatureVerifier(nil).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("referral with key ID", func(t *testing.T) {
		document, _, publicKey := CreateTestDocument(1)
		expected, _ := ParseDocument(document.Data())
		err := NewDocumentSignatureVerifier(&crypto.StaticKeyResolver{Key: publicKey}).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("wrong key", func(t *testing.T) {
		attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		document, _, _ := CreateTestDocument(1)
		expected, _ := ParseDocument(document.Data())
		err := NewDocumentSignatureVerifier(&crypto.StaticKeyResolver{Key: attackerKey.Public()}).Verify(expected)
		assert.EqualError(t, err, "failed to verify message: failed to verify signature using ecdsa")
	})
	t.Run("unsupported input", func(t *testing.T) {
		err := NewDocumentSignatureVerifier(nil).Verify(nil)
		assert.EqualError(t, err, "unsupported document")
	})
	t.Run("key type is incorrect", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		document := d.(*document)
		document.signingKey = jwk.NewSymmetricKey()
		err := NewDocumentSignatureVerifier(nil).Verify(document)
		assert.EqualError(t, err, "failed to verify message: invalid key type []uint8. *ecdsa.PublicKey is required")
	})
	t.Run("unable to derive key from JWK", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		document := d.(*document)
		document.signingKey = jwk.NewOKPPublicKey()
		err := NewDocumentSignatureVerifier(nil).Verify(document)
		assert.EqualError(t, err, "failed to build public key: invalid curve algorithm P-invalid")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		err := NewDocumentSignatureVerifier(keyResolver).Verify(d)
		assert.Contains(t, err.Error(), "failed")
	})
}

type trackingJWSSigner struct {
	headers map[string]interface{}
	payload []byte
	kid     string
}

func (t *trackingJWSSigner) SignJWS(payload []byte, protectedHeaders map[string]interface{}, kid string) (string, jwa.SignatureAlgorithm, error) {
	t.payload = payload
	t.headers = protectedHeaders
	t.kid = kid
	return "fine JWS", jwa.ES256, nil
}
