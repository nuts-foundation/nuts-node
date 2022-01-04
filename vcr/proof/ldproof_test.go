package proof

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
		proofMap := map[string]interface{}{}
		_ = proofBuilder.copy(options, &proofMap)
		assert.NoError(t, err, "expected NewLDProofBuilder to succeed")

		canonicalizedDocument, err := proofBuilder.canonicalize(document)
		assert.NoError(t, err, "expected canonicalization to succeed")

		canonicalizedProof, err := proofBuilder.canonicalize(proofMap)
		assert.NoError(t, err, "expected canonicalization to succeed")

		tbs, err := proofBuilder.CreateToBeSigned(canonicalizedDocument, canonicalizedProof)
		assert.NoError(t, err, "expected ToBeSigned creation to succeed")
		expectedTbs := []byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, 0x3f, 0x9c, 0x98, 0xf, 0xe3, 0xbf, 0x97, 0xef, 0xda, 0x13, 0x74, 0x9a, 0xcf, 0xc8, 0x41, 0xb7, 0xe7, 0xe9, 0x5c, 0x29, 0x1, 0xaa, 0x4e, 0x13, 0xf5, 0xdd, 0x5a, 0x12, 0xce, 0xac, 0x15, 0xe}

		assert.Equal(t, expectedTbs, tbs)
	})
}

func TestLdProofBuilder_Sign(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		options := ProofOptions{
			Created: time.Date(2021, 12, 22, 15, 21, 12, 0, time.FixedZone("Amsterdam", int(2*time.Hour.Seconds()))),
		}
		ldproof, _ := NewLDProofBuilder(document, options)
		pemKey := "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC4R1AmYYyE47FMZgo708NhFU+t+VWn133PYGt/WYmD5BnKj679\nYiUmyrC3hX6oZfo4eVpOkycxZvGgXCLQGuDp45XfZkdsjqs3o62En4YjlHWxgeGm\nkiRqGfZ3sJ3u5WZ2xwapdZY3/2T/oOV5ri8SktTvmVGCyhwFuJC/NbJMEwIDAQAB\nAoGAZXNdPMQXiFGSGm1S1P0QYzJIW48ZCP4p1TFP/RxeCK5bRJk1zWlq6qBMCb0E\nrdD2oICupvN8cEYsYAxZXhhuGWZ60vggbqTTa+4LXB+SGCbKMX711ZoQHdY7rnaF\nb/Udf4wTLD1yAslx1TrHkV56OfuJcEdWC7JWqyNXQoxedwECQQDZvcEmBT/Sol/S\nAT5ZSsgXm6xCrEl4K26Vyw3M5UShRSlgk12gfqqSpdeP5Z7jdV/t5+vD89OJVfaa\nTw4h9BibAkEA2Khe03oYQzqP1V4YyV3QeC4yl5fCBr8HRyOMC4qHHKQqBp2VDUyu\nRBJhTqqf1ErzUBkXseawNxtyuPmPrMSl6QJAQOgfu4W1EMT2a1OTkmqIWwE8yGMz\nQ28u99gftQRjAO/s9az4K++WSUDGkU6RnpxOjEymKzNzy2ykpjsKq3RoIQJAA+XL\nhuxsYVE9Yy5FLeI1LORP3rBJOkvXeq0mCNMeKSK+6s2M7+dQP0NBYuPo6i3LAMbi\nyT2IMAWbY76Bmi8TeQJAfdLJGwiDNIhTVYHxvDz79ANzgRAd1kPKPddJZ/w7Gfhm\n8Mezti8HCizDxPb+H8HlJMSkfoHx1veWkdLaPWRFrA==\n-----END RSA PRIVATE KEY-----\n                  "
		block, _ := pem.Decode([]byte(pemKey))
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if !assert.NoError(t, err) {
			return
		}
		key := crypto.NewRSATestKey("did:nuts:123#abc", privateKey)
		signedDoc, err := ldproof.Sign(key)
		assert.NoError(t, err)

		docAsJson, _ := json.Marshal(signedDoc)
		t.Log(string(docAsJson))
	})
}

//func TestLDProof_Copy(t *testing.T) {
//	t.Run("ok - copies the object", func(t *testing.T) {
//		type testStruct struct {
//			Key *string
//		}
//		testValue := "value"
//		testInput := &testStruct{Key: &testValue}
//		ldproof := ldProofBuilder{input: testInput}
//		proofCopy := LDProof{}
//		_ = ldproof.copy(proofCopy)
//
//		assert.IsType(t, &testStruct{}, copyResult)
//		testCopy := copyResult.(*testStruct)
//
//		assert.NoError(t, err)
//		assert.Equal(t, "value", *testCopy.Key, "the copy should contain the Keys value")
//		*testInput.Key = "newValue"
//		assert.Equal(t, "value", *testCopy.Key, "the copy should not change with the original")
//	})
//}
