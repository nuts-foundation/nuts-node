package proof

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Proofstruct(t *testing.T) {

	t.Run("unmarshal signed doc into SignedDocument struct", func(t *testing.T) {

		jsonldDocument := `{
		"@context": [
			{"title": "https://schema.org#title"},
			"https://w3id.org/security/suites/ed25519-2020/v1"
			],
		"title": "Hello world!",
		"proof": {
			 "type": "Ed25519Signature2020",
			 "created": "2020-11-05T19:23:24Z",
			 "verificationMethod": "https://ldi.example/issuer#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG",
			 "proofPurpose": "assertionMethod",
			 "proofValue": "z4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYVQeVbY8nQAVHMrXFkXJpmEcqdoDwLWxaqA3Q1geV6"
		}
	}`

		signedDoc := SignedDocument{}
		err := json.Unmarshal([]byte(jsonldDocument), &signedDoc)
		assert.NoError(t, err)
		assert.Equal(t, "Ed25519Signature2020", signedDoc.FirstProof()["type"])
		assert.Equal(t, "Hello world!", signedDoc["title"])
		t.Logf("%#v", signedDoc)
	})
}

func TestSignedDocument_FirstProof(t *testing.T) {
	jsonDocumentWithoutProof := `{
		"title": "Hello world!"
	}`

	jsonDocumentWithSingleProof := `{
		"title": "Hello world!",
		"proof": {
			 "type": "firstProof"
		}
	}`

	jsonDocumentWithMultipleProof := `{
		"title": "Hello world!",
		"proof": [{
			 "type": "firstProof"
		}, {
			 "type": "secondProof"
		}]
	}`
	t.Run("no proof", func(t *testing.T) {
		signedDoc := SignedDocument{}
		err := json.Unmarshal([]byte(jsonDocumentWithoutProof), &signedDoc)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, signedDoc.FirstProof())
	})

	t.Run("single proof", func(t *testing.T) {
		signedDoc := SignedDocument{}
		err := json.Unmarshal([]byte(jsonDocumentWithSingleProof), &signedDoc)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "firstProof", signedDoc.FirstProof()["type"])
	})

	t.Run("multiple proofs", func(t *testing.T) {
		signedDoc := SignedDocument{}
		err := json.Unmarshal([]byte(jsonDocumentWithMultipleProof), &signedDoc)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "firstProof", signedDoc.FirstProof()["type"])
	})
}
