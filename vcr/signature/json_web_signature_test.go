package signature

import (
	"encoding/hex"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJsonWebSignature2020_CanonicalizeDocument(t *testing.T) {

	t.Run("a doc without context gives an empty result", func(t *testing.T) {
		sig := JsonWebSignature2020{}
		doc := map[string]interface{}{"title": "Hello world"}
		res, err := sig.CanonicalizeDocument(doc)
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, res)
	})

	t.Run("simple document with context", func(t *testing.T) {
		sig := JsonWebSignature2020{}
		doc := map[string]interface{}{
			"@context": []interface{}{
				map[string]interface{}{"title": "http://schema.org/title"},
			},
			"title": "Hello world!",
		}

		res, err := sig.CanonicalizeDocument(doc)
		assert.NoError(t, err)
		assert.Equal(t, "_:c14n0 <http://schema.org/title> \"Hello world!\" .\n", string(res))
	})

	t.Run("simple document with resolvable context", func(t *testing.T) {
		sig := JsonWebSignature2020{}
		doc := map[string]interface{}{
			"@context": []interface{}{
				"https://schema.org",
			},
			"title": "Hello world!",
		}

		res, err := sig.CanonicalizeDocument(doc)
		assert.NoError(t, err)
		assert.Equal(t, "_:c14n0 <http://schema.org/title> \"Hello world!\" .\n", string(res))
	})
}

func TestJsonWebSignature2020_CalculateDigest(t *testing.T) {
	t.Run("it calculates the document digest", func(t *testing.T) {
		sig := JsonWebSignature2020{}
		doc := []byte("foo")
		result := sig.CalculateDigest(doc)
		expected, _ := hex.DecodeString("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
		assert.Equal(t, expected, result)
	})
}

func TestJsonWebSignature2020_GetType(t *testing.T) {
	t.Run("it returns its type", func(t *testing.T) {
		sig := JsonWebSignature2020{}
		assert.Equal(t, ssi.JsonWebSignature2020, sig.GetType())
	})
}

func Test_detachedJWSHeaders(t *testing.T) {
	t.Run("it returns a detached JWS header", func(t *testing.T) {
		headers := detachedJWSHeaders()

		assert.Equal(t, false, headers["b64"])
		assert.Equal(t, []string{"b64"}, headers["crit"])
	})
}

func TestJsonWebSignature2020_Sign(t *testing.T) {
	t.Run("it returns the signing result", func(t *testing.T) {
		doc := []byte("foo")
		sig := JsonWebSignature2020{}
		result, err := sig.Sign(doc, crypto.NewTestKey("did:nuts:123#abc"))
		assert.NoError(t, err)
		assert.Contains(t, string(result), "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19")
	})
}
