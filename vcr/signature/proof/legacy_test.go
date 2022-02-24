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
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestLegacyLDProof_Verify(t *testing.T) {
	credentialJson, err := os.ReadFile("../../test/vc.json")
	if !assert.NoError(t, err) {
		return
	}
	pkeJSON, _ := os.ReadFile("../../test/public.json")
	if !assert.NoError(t, err) {
		return
	}

	pke := storage.PublicKeyEntry{}
	if !assert.NoError(t, json.Unmarshal(pkeJSON, &pke)) {
		return
	}
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("it verifies a valid signature", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)

		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signature.LegacyNutsSuite{}, pk)
		assert.NoError(t, verifyError)
	})

	t.Run("it fails when the signature is invalid", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)

		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)

		// add extra field to the signature so the digest is different
		legacyProof.ProofPurpose = "failing a test"

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "invalid proof signature: failed to verify signature using ecdsa")
	})

	t.Run("it fails when the signature has an invalid format", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)
		legacyProof.Jws = "invalid jws"

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "invalid 'jws' value in proof")
	})

	t.Run("it fails when the signature is invalid base64", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)

		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)
		legacyProof.Jws = "header..signature"

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "illegal base64 data at input byte 8")
	})

	t.Run("it fails when the suite can not canonicalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		signatureSuiteMock := signature.NewMockSuite(ctrl)
		signatureSuiteMock.EXPECT().CanonicalizeDocument(gomock.Any()).Return(nil, errors.New("error with canonicalization"))

		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signatureSuiteMock, pk)
		assert.EqualError(t, verifyError, "error with canonicalization")
	})

	t.Run("it fails with unknown key type", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		signedDoc, _ := NewSignedDocument(credentialToVerify)
		legacyProof := LegacyLDProof{}
		signedDoc.UnmarshalProofValue(&legacyProof)

		verifyError := legacyProof.Verify(signedDoc.DocumentWithoutProof(), signature.LegacyNutsSuite{}, "unknown type")
		assert.EqualError(t, verifyError, "could not determine signature algorithm for key type 'string'")

	})
}

func TestLegacyLDProof_Sign(t *testing.T) {
	t.Run("it signs a document", func(t *testing.T) {
		now := time.Now()
		expires := now.Add(20 * time.Hour)
		domain := "chateau Torquilstone"

		pOptions := ProofOptions{
			Created:        now,
			Domain:         &domain,
			ExpirationDate: &expires,
			ProofPurpose:   "assertion",
		}

		ldProof := NewLegacyLDProof(pOptions)

		document := map[string]interface{}{
			"@context": []interface{}{
				map[string]interface{}{"title": "https://schema.org#title"},
			},
			"title": "Hello world!",
		}

		kid := "did:nuts:123#abc"
		testKey := crypto.NewTestKey(kid)

		result, err := ldProof.Sign(document, signature.LegacyNutsSuite{}, testKey)
		assert.NoError(t, err,
			"unexpected error while signing the proof")

		if !assert.NoError(t, err) || !assert.NotNil(t, result) {
			return
		}
		signedDocument := result.(SignedDocument)

		proofToVerify := LegacyLDProof{}
		err = signedDocument.UnmarshalProofValue(&proofToVerify)
		assert.NoError(t, err)
		assert.Equal(t, domain, *proofToVerify.Domain)

		docWithoutProof := signedDocument.DocumentWithoutProof()

		err = proofToVerify.Verify(docWithoutProof, signature.LegacyNutsSuite{}, testKey.Public())
		assert.NoError(t, err)
	})
}
