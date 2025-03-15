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
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestLDProof_Verify(t *testing.T) {
	vc_0 := `{
		 "@context": [
			  "https://www.w3.org/2018/credentials/v1",
			  "https://www.w3.org/2018/credentials/examples/v1",
			  "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
		 ],
		 "id": "http://example.gov/credentials/3732",
		 "type": ["VerifiableCredential", "UniversityDegreeCredential"],
		 "issuer": { "id": "https://example.com/issuer/123" },
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
	require.NoError(t, json.Unmarshal([]byte(rawVerificationMethod), &verificationMethod))
	pk, err := verificationMethod.PublicKey()
	require.NoError(t, err)

	signedDocument := SignedDocument{}
	require.NoError(t, json.Unmarshal([]byte(vc_0), &signedDocument))

	contextLoader := jsonld.NewTestJSONLDManager(t).DocumentLoader()

	t.Run("ok - JSONWebSignature2020 test vector", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
		assert.NoError(t, err, "expected no error when verifying the JSONWebSignature2020 test vector")
	})

	t.Run("it handles an error while canonicalizing the document", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))

		ctrl := gomock.NewController(t)

		mockSuite := signature.NewMockSuite(ctrl)
		mockSuite.EXPECT().CanonicalizeDocument(signedDocument.DocumentWithoutProof()).Return(nil, errors.New("foo"))
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), mockSuite, pk)
		assert.EqualError(t, err, "foo")
	})

	t.Run("it handles an error while canonicalizing the proof", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))

		ctrl := gomock.NewController(t)

		mockSuite := signature.NewMockSuite(ctrl)

		// handle first call for the document
		mockSuite.EXPECT().CanonicalizeDocument(signedDocument.DocumentWithoutProof()).Return(nil, nil)
		// handle second call for proof and return error
		mockSuite.EXPECT().CanonicalizeDocument(gomock.Any()).Return(nil, errors.New("foo"))

		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), mockSuite, pk)
		assert.EqualError(t, err, "unable to canonicalize proof: foo")
	})

	t.Run("it handles an error for an unknown public key type", func(t *testing.T) {
		pk := "foo"
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
		assert.EqualError(t, err, "could not determine signature algorithm for key type 'string'")
	})

	t.Run("invalid jws format", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))
		// invalid format, it should have 2 dots
		ldProof.JWS = "abc"
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
		assert.EqualError(t, err, "invalid 'jws' value in proof")

	})

	t.Run("jws signature nog valid b64 encoded", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))
		// invalid format, it should have 2 dots
		ldProof.JWS = "header..%%"
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
		assert.EqualError(t, err, "could not base64 decode signature: illegal base64 data at input byte 0")

	})

	t.Run("invalid signature", func(t *testing.T) {
		ldProof := LDProof{}
		assert.NoError(t, signedDocument.UnmarshalProofValue(&ldProof))
		// signature with some changed characters
		ldProof.JWS = "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MJ5GwWRMsadCyLNXU_flgJtsS32584MydBxBuyups_cM0sbU3abTEOMyUvmLNcKOwOBE1MfDoB1_YY425W3sAg"
		err = ldProof.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader}, pk)
		assert.EqualError(t, err, "invalid proof signature: failed to match EdDSA signature")

	})
}

func TestLDProof_Sign(t *testing.T) {
	document := map[string]interface{}{
		"@context": []interface{}{
			map[string]interface{}{"title": "http://schema.org#title"},
		},
		"title": "Hello world!",
	}

	kid := "did:nuts:123#abc"
	contextLoader := jsonld.NewTestJSONLDManager(t).DocumentLoader()

	cryptoInstance := crypto.NewMemoryCryptoInstance(t)
	_, key, _ := cryptoInstance.New(audit.TestContext(), crypto.StringNamingFunc(kid))
	t.Run("sign and verify a document", func(t *testing.T) {
		now := time.Now()
		expires := now.Add(20 * time.Hour)
		challenge := "stand on 1 leg for 2 hours"
		domain := "chateau Torquilstone"

		pOptions := ProofOptions{
			Created:      now,
			Domain:       &domain,
			Challenge:    &challenge,
			Expires:      &expires,
			ProofPurpose: "assertion",
		}

		ldProof := NewLDProof(pOptions)

		result, err := ldProof.Sign(audit.TestContext(), document, signature.JSONWebSignature2020{ContextLoader: contextLoader, Signer: cryptoInstance}, kid)
		require.NoError(t, err)
		require.NotNil(t, result)
		signedDocument := result.(SignedDocument)
		t.Logf("%+v", signedDocument)

		proofToVerify := LDProof{}
		err = signedDocument.UnmarshalProofValue(&proofToVerify)
		assert.NoError(t, err)
		assert.Equal(t, domain, *proofToVerify.Domain)
		assert.Equal(t, challenge, *proofToVerify.Challenge)

		err = proofToVerify.Verify(signedDocument.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: contextLoader, Signer: cryptoInstance}, key)
		assert.NoError(t, err)
	})

	t.Run("it handles a failed document canonicalization", func(t *testing.T) {
		ldProof := LDProof{}

		ctrl := gomock.NewController(t)

		mockSuite := signature.NewMockSuite(ctrl)

		// handle first call for the document
		mockSuite.EXPECT().CanonicalizeDocument(document).Return(nil, errors.New("foo"))
		mockSuite.EXPECT().GetType().Return(ssi.JsonWebSignature2020)
		result, err := ldProof.Sign(nil, document, mockSuite, kid)
		assert.EqualError(t, err, "foo")
		assert.Nil(t, result)
	})

	t.Run("it handles a failed proof canonicalization", func(t *testing.T) {
		ldProof := LDProof{}

		ctrl := gomock.NewController(t)

		mockSuite := signature.NewMockSuite(ctrl)

		// handle first call for the document
		mockSuite.EXPECT().CanonicalizeDocument(document).Return(nil, nil)
		mockSuite.EXPECT().CanonicalizeDocument(gomock.Any()).Return(nil, errors.New("foo"))
		mockSuite.EXPECT().GetType().Return(ssi.JsonWebSignature2020)
		result, err := ldProof.Sign(nil, document, mockSuite, kid)
		assert.EqualError(t, err, "unable to canonicalize proof: foo")
		assert.Nil(t, result)
	})

	t.Run("it handles a signing error", func(t *testing.T) {
		ldProof := LDProof{}

		result, err := ldProof.Sign(audit.TestContext(), document, signature.JSONWebSignature2020{ContextLoader: contextLoader, Signer: crypto.NewMemoryCryptoInstance(t)}, "kid")

		assert.EqualError(t, err, "error while signing: private key not found")
		assert.Nil(t, result)
	})
}

func TestProofOptions_ValidAt(t *testing.T) {
	at := time.Now()
	skew := 5 * time.Second
	t.Run("valid", func(t *testing.T) {
		exp := at.Add(1 * time.Hour)
		valid := ProofOptions{
			Created: at.Add(-1 * time.Hour),
			Expires: &exp,
		}.ValidAt(at, skew)
		assert.True(t, valid)
	})

	t.Run("not yet valid", func(t *testing.T) {
		valid := ProofOptions{
			Created: at.Add(time.Hour),
		}.ValidAt(at, skew)
		assert.False(t, valid)
	})

	t.Run("expiration not set", func(t *testing.T) {
		valid := ProofOptions{
			Created: at.Add(-1 * time.Hour),
		}.ValidAt(at, skew)
		assert.True(t, valid)
	})

	t.Run("expired", func(t *testing.T) {
		exp := at.Add(-1 * time.Hour)
		valid := ProofOptions{
			Created: at.Add(-2 * time.Hour),
			Expires: &exp,
		}.ValidAt(at, skew)
		assert.False(t, valid)
	})
}
