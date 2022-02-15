package signature

import (
	"encoding/hex"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLegacyNutsSuite_CanonicalizeDocument(t *testing.T) {
	t.Run("it make it json", func(t *testing.T) {
		sig := LegacyNutsSuite{}
		doc := map[string]interface{}{"title": "Hello world"}
		res, err := sig.CanonicalizeDocument(doc)
		assert.NoError(t, err)
		assert.Equal(t, []byte("{\"title\":\"Hello world\"}"), res)
	})
}

func TestLegacyNutsSuite_CalculateDigest(t *testing.T) {
	t.Run("it calculates the document digest", func(t *testing.T) {
		sig := LegacyNutsSuite{}
		doc := []byte("foo")
		result := sig.CalculateDigest(doc)
		expected, _ := hex.DecodeString("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
		assert.Equal(t, expected, result)
	})
}
func TestLegacyNutsSuite_GetType(t *testing.T) {
	t.Run("it returns its type", func(t *testing.T) {
		sig := LegacyNutsSuite{}
		assert.Equal(t, ssi.JsonWebSignature2020, sig.GetType())
	})
}

func TestLegacyNutsSuite_Sign(t *testing.T) {
	t.Run("it returns the signing result", func(t *testing.T) {
		doc := []byte("foo")
		sig := LegacyNutsSuite{}
		result, err := sig.Sign(doc, crypto.NewTestKey("did:nuts:123#abc"))
		assert.NoError(t, err)
		assert.Contains(t, string(result), "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19")
	})
}
