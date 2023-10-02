package didkey

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResolver_Resolve(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		const expected = `
{
  "@context": [
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
    "https://www.w3.org/ns/did/v1"
  ],
  "assertionMethod": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "authentication": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityDelegation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityInvocation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "keyAgreement": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "verificationMethod": [
    {
      "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "publicKeyJwk": {
        "crv": "Ed25519",
        "kty": "OKP",
        "x": "AS5vzONnAdx5FIjg0LF0XMHjOkwcn8xBxjvTQ9u-CXDm"
      },
      "type": "JsonWebKey2020"
    }
  ]
}
`
		r := Resolver{}
		doc, md, err := r.Resolve(did.MustParseDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), nil)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, md)
		docJSON, _ := doc.MarshalJSON()
		assert.JSONEq(t, expected, string(docJSON))
	})
}
