package proof

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
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

		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))
		credentialToVerify.Proof = nil

		verifyError := legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, pk)
		assert.NoError(t, verifyError)
	})

	t.Run("it fails when the signature is invalid", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))

		// add extra field to the signature so the digest is different
		legacyProof[0].ProofPurpose = "failing a test"
		credentialToVerify.Proof = nil
		verifyError := legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "invalid proof signature: failed to verify signature using ecdsa")
	})

	t.Run("it fails when the signature has an invalid format", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))

		legacyProof[0].Jws = "invalid jws"
		credentialToVerify.Proof = nil
		verifyError := legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "invalid 'jws' value in proof")
	})

	t.Run("it fails when the signature is invalid base64", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))

		legacyProof[0].Jws = "header..signature"
		credentialToVerify.Proof = nil
		verifyError := legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, pk)
		assert.EqualError(t, verifyError, "illegal base64 data at input byte 8")
	})

	t.Run("it fails when the suite can not canonicalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		signatureSuiteMock := signature.NewMockSuite(ctrl)
		signatureSuiteMock.EXPECT().CanonicalizeDocument(gomock.Any()).Return(nil, errors.New("error with canonicalization"))

		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))
		credentialToVerify.Proof = nil

		verifyError := legacyProof[0].Verify(credentialToVerify, signatureSuiteMock, pk)
		assert.EqualError(t, verifyError, "error with canonicalization")
	})

	t.Run("it fails with unknown key type", func(t *testing.T) {
		credentialToVerify := vc.VerifiableCredential{}
		_ = json.Unmarshal(credentialJson, &credentialToVerify)
		legacyProof := make([]LegacyLDProof, 1)
		assert.NoError(t, credentialToVerify.UnmarshalProofValue(&legacyProof))

		credentialToVerify.Proof = nil
		verifyError := legacyProof[0].Verify(credentialToVerify, signature.LegacyNutsSuite{}, "unknonw type")
		assert.EqualError(t, verifyError, "invalid key type 'string' for jwk.New")

	})
}
