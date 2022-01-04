package proof

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	_ "github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var document = map[string]interface{}{
	"@context": []string{"https://schema.org"},
	"@type":    "Message",
	"text":     "This is the message body",
}

func TestLDProof_CreateToBeSigned(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		domain := "kik-v"

		options := ProofOptions{
			Created: time.Date(2021, 12, 22, 15, 21, 12, 0, time.FixedZone("Amsterdam", int(2*time.Hour.Seconds()))),
			Domain:  &domain,
		}
		proofBuilder, err := NewLDProofBuilder(document, options)
		ldProofBuilder := proofBuilder.(*ldProofManager)

		proofMap := map[string]interface{}{}
		_ = ldProofBuilder.copy(options, &proofMap)
		assert.NoError(t, err, "expected NewLDProofBuilder to succeed")

		canonicalizedDocument, err := ldProofBuilder.canonicalize(document)
		assert.NoError(t, err, "expected canonicalization to succeed")

		canonicalizedProof, err := ldProofBuilder.canonicalize(proofMap)
		assert.NoError(t, err, "expected canonicalization to succeed")

		tbs, err := ldProofBuilder.CreateToBeSigned(canonicalizedDocument, canonicalizedProof)
		assert.NoError(t, err, "expected ToBeSigned creation to succeed")
		expectedTbs := []byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, 0x3f, 0x9c, 0x98, 0xf, 0xe3, 0xbf, 0x97, 0xef, 0xda, 0x13, 0x74, 0x9a, 0xcf, 0xc8, 0x41, 0xb7, 0xe7, 0xe9, 0x5c, 0x29, 0x1, 0xaa, 0x4e, 0x13, 0xf5, 0xdd, 0x5a, 0x12, 0xce, 0xac, 0x15, 0xe}

		assert.Equal(t, expectedTbs, tbs)
	})
}

const pemKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC4R1AmYYyE47FMZgo708NhFU+t+VWn133PYGt/WYmD5BnKj679
YiUmyrC3hX6oZfo4eVpOkycxZvGgXCLQGuDp45XfZkdsjqs3o62En4YjlHWxgeGm
kiRqGfZ3sJ3u5WZ2xwapdZY3/2T/oOV5ri8SktTvmVGCyhwFuJC/NbJMEwIDAQAB
AoGAZXNdPMQXiFGSGm1S1P0QYzJIW48ZCP4p1TFP/RxeCK5bRJk1zWlq6qBMCb0E
rdD2oICupvN8cEYsYAxZXhhuGWZ60vggbqTTa+4LXB+SGCbKMX711ZoQHdY7rnaF
b/Udf4wTLD1yAslx1TrHkV56OfuJcEdWC7JWqyNXQoxedwECQQDZvcEmBT/Sol/S
AT5ZSsgXm6xCrEl4K26Vyw3M5UShRSlgk12gfqqSpdeP5Z7jdV/t5+vD89OJVfaa
Tw4h9BibAkEA2Khe03oYQzqP1V4YyV3QeC4yl5fCBr8HRyOMC4qHHKQqBp2VDUyu
RBJhTqqf1ErzUBkXseawNxtyuPmPrMSl6QJAQOgfu4W1EMT2a1OTkmqIWwE8yGMz
Q28u99gftQRjAO/s9az4K++WSUDGkU6RnpxOjEymKzNzy2ykpjsKq3RoIQJAA+XL
huxsYVE9Yy5FLeI1LORP3rBJOkvXeq0mCNMeKSK+6s2M7+dQP0NBYuPo6i3LAMbi
yT2IMAWbY76Bmi8TeQJAfdLJGwiDNIhTVYHxvDz79ANzgRAd1kPKPddJZ/w7Gfhm
8Mezti8HCizDxPb+H8HlJMSkfoHx1veWkdLaPWRFrA==
-----END RSA PRIVATE KEY-----`

func TestLdProofManager_Sign(t *testing.T) {

	block, _ := pem.Decode([]byte(pemKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - sign and verify own document", func(t *testing.T) {
		options := ProofOptions{
			Created: time.Date(2021, 12, 22, 15, 21, 12, 0, time.FixedZone("Amsterdam", int(2*time.Hour.Seconds()))),
		}
		ldproof, _ := NewLDProofBuilder(document, options)

		key := crypto.NewRSATestKey("did:nuts:123#abc", privateKey)
		signedDoc, err := ldproof.Sign(key)
		assert.NoError(t, err)

		docAsJson, _ := json.Marshal(signedDoc)
		t.Log(string(docAsJson))

		verifier, _ := NewLDProofVerifier()
		err = verifier.Verify(signedDoc, privateKey.PublicKey)
		assert.NoError(t, err)
	})
}

func TestLdProofManager_Verify(t *testing.T) {
	block, _ := pem.Decode([]byte(pemKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - JsonWebSignature2020 test vector", func(t *testing.T) {
		vc_0 := `{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "id": "http://example.gov/credentials/3732",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": {
      "id": "https://example.com/issuer/123"
    },
    "issuanceDate": "2020-03-10T04:24:12.164Z",
    "credentialSubject": {
      "id": "did:example:456",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "2019-12-11T03:50:55Z",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MJ5GwWRMsadCyLNXU_flgJtsS32584MydBxBuygps_cM0sbU3abTEOMyUvmLNcKOwOBE1MfDoB1_YY425W3sAg",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "https://example.com/issuer/123#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc"
    }
  }`

		rawVerificationMethod := `{
 "id": "did:key:abc#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc",
 "type": "JsonWebKey2020",
 "controller": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
 "publicKeyJwk": {
   "kty": "OKP",
   "crv": "Ed25519",
   "x": "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ"
 }
}`
		verificationMethod := did.VerificationMethod{}
		if !assert.NoError(t, json.Unmarshal([]byte(rawVerificationMethod), &verificationMethod)) {
			return
		}

		signedDocument := map[string]interface{}{}
		err = json.Unmarshal([]byte(vc_0), &signedDocument)
		if !assert.NoError(t, err) {
			return
		}
		verifier, _ := NewLDProofVerifier()
		publicKey, err := verificationMethod.PublicKey()
		if !assert.NoError(t, err) {
			return
		}
		err = verifier.Verify(signedDocument, publicKey)
		assert.NoError(t, err)
	})

	t.Run("ok - rsa test from the json-ld playground", func(t *testing.T) {
		
		rawDocument := `{
  "@context": [
    {
      "@version": 1.1
    },
    "https://schema.org",
    "https://w3id.org/security/v2"
  ],
  "@type": "Message",
  "text": "This is the message body",
  "proof": {
    "type": "RsaSignature2018",
    "created": "2022-01-04T13:34:23Z",
    "creator": "https://example.com/jdoe/keys/1",
    "domain": "json-ld.org",
    "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DA_vtXm7pVUqt_X4xioFN2ajxp2rDNFjXrOQaA7_dRz-WI-w8j2Ew1VJqKe9rpCQu3fo5cmjho2pCOsvR5aiPwn5wEZQHiiRvIPvrzTXUPn0eGpbjONW1dj-kIrAw_zVWlIWDv6n51IJTdHK1mVEilhNVhAj3UUhHEzsBWeLoOM",
    "nonce": "c11cfad6"
  }
}`

		//t.Skip("rsa currently not supported")
		signedDocument := map[string]interface{}{}
		err := json.Unmarshal([]byte(rawDocument), &signedDocument)
		if !assert.NoError(t, err) {
			return
		}
		verifier, _ := NewLDProofVerifier()
		err = verifier.Verify(signedDocument, privateKey.PublicKey)
		assert.NoError(t, err)
	})

}
