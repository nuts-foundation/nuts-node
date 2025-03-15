/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package proof

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignedDocument_UnmarshalProofValue(t *testing.T) {

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
