package proof

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
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
		proof := vc.JSONWebSignature2020Proof{}
		assert.NoError(t, signedDoc.UnmarshalProofValue(&proof))
		assert.Equal(t, ssi.ProofType("Ed25519Signature2020"), proof.Type)
		assert.Equal(t, "Hello world!", signedDoc["title"])
		t.Logf("%#v", signedDoc)
	})
}
