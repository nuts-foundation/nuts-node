package signature

import (
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
