package didkey

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResolver_Resolve(t *testing.T) {
	resolver := Resolver{}
	type testCase struct {
		name string
		did  string
		jwk  map[string]interface{}
	}

	// Fixtures were taken from https://github.com/digitalbazaar/did-method-key/blob/main/test/driver.spec.js
	testCases := []testCase{
		{
			name: "ed25519 #1",
			did:  "did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T",
			jwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "cwGXz9hryEvuEo-cBcLTBWnnr9kBjx2_1xTMndtgth4",
			},
		},
		{
			name: "ed25519 #2",
			did:  "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			jwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "lJZrfAjkBXdfjebMHEUI9usidAPhAlssitLXR3OYxbI",
			},
		},
		{
			name: "secp256",
			did:  "did:key:zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "sYLQHOy9TNAWwFcAlpxkqRA5OutpWCrVPEWsgeli_KA",
				"y":   "l5Jr9_48oPJWHwuVmH_VZVquGe-U8RtnR-McN4tdYhs",
			},
		},
		{
			name: "secp256k1",
			did:  "did:key:zQ3shbgnTGcgBpXPdBjDur3ATMDWhS7aPs6FRFkWR19Lb9Zwz",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "secp256k1",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID(tc.did), nil)
			require.NoError(t, err)
			require.NotNil(t, doc)
			require.NotNil(t, md)
			// Assert getting the public key
			vm := doc.VerificationMethod[0]
			publicKey, err := vm.PublicKey()
			require.NoError(t, err, "failed to get public key")
			require.NotNil(t, publicKey, "public key is nil")
			// Assert JWK type
			jwk, err := vm.JWK()

			require.NoError(t, err, "failed to get JWK")
			jwkJSON, _ := json.Marshal(jwk)
			var jwkAsMap map[string]interface{}
			_ = json.Unmarshal(jwkJSON, &jwkAsMap)
			assert.Equal(t, tc.jwk, jwkAsMap)
		})
	}

	t.Run("verify created DID document", func(t *testing.T) {
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
        "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
      },
      "type": "JsonWebKey2020"
    }
  ]
}
`
		doc, md, err := resolver.Resolve(did.MustParseDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), nil)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, md)
		docJSON, _ := doc.MarshalJSON()
		assert.JSONEq(t, expected, string(docJSON))
		// Test the public key
		publicKey, err := doc.VerificationMethod[0].PublicKey()
		require.NoError(t, err)
		require.IsType(t, ed25519.PublicKey{}, publicKey)
	})
}
