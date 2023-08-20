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

package verifier

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func testCredential(t *testing.T) vc.VerifiableCredential {
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("../test/vc.json")
	require.NoError(t, json.Unmarshal(vcJSON, &subject))
	return subject
}

func Test_verifier_Validate(t *testing.T) {
	const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

	// load pub key
	pke := spi.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("../test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(pk, nil)

		err := instance.Validate(testCredential(t), nil)

		assert.NoError(t, err)
	})

	t.Run("type", func(t *testing.T) {
		t.Run("incorrect number of types", func(t *testing.T) {
			ctx := newMockContext(t)
			instance := ctx.verifier

			err := instance.Validate(vc.VerifiableCredential{Type: []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("a"), ssi.MustParseURI("b")}}, nil)

			assert.EqualError(t, err, "verifiable credential must list at most 2 types")
		})
		t.Run("does not contain v1 context", func(t *testing.T) {
			ctx := newMockContext(t)
			instance := ctx.verifier

			err := instance.Validate(vc.VerifiableCredential{Type: []ssi.URI{ssi.MustParseURI("foo"), ssi.MustParseURI("bar")}}, nil)

			assert.EqualError(t, err, "verifiable credential does not list 'VerifiableCredential' as type")
		})
	})

	t.Run("error - invalid vm", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier

		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		_ = vc2.UnmarshalProofValue(&pr)
		u := ssi.MustParseURI(vc2.Issuer.String() + "2")
		pr[0].VerificationMethod = u
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Validate(vc2, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "verification method is not of issuer")
	})

	t.Run("error - wrong hashed payload", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		vc2 := testCredential(t)
		vc2.IssuanceDate = time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)

		err := instance.Validate(vc2, nil)

		assert.ErrorContains(t, err, "failed to verify signature")
	})

	t.Run("error - wrong hashed proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Created = time.Now()
		vc2.Proof = []interface{}{pr[0]}

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)

		err := instance.Validate(vc2, nil)

		assert.ErrorContains(t, err, "failed to verify signature")
	})

	t.Run("error - no proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		vc2 := testCredential(t)
		vc2.Proof = []interface{}{}

		err := instance.Validate(vc2, nil)

		assert.ErrorContains(t, err, "unable to extract ldproof from signed document: json: cannot unmarshal array into Go value of type proof.LDProof")
	})

	t.Run("error - wrong jws in proof", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)
		instance := ctx.verifier
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = ""
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Validate(vc2, nil)

		assert.ErrorContains(t, err, "invalid 'jws' value in proof")
	})

	t.Run("error - wrong base64 encoding in jws", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)
		instance := ctx.verifier
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = "abac..ab//"
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Validate(vc2, nil)

		assert.ErrorContains(t, err, "illegal base64 data")
	})

	t.Run("error - resolving key", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(nil, errors.New("b00m!"))

		err := instance.Validate(testCredential(t), nil)

		assert.Error(t, err)
	})

}

func TestVerifier_Verify(t *testing.T) {
	const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("error - unknown credential", func(t *testing.T) {
		t.Skip("unknown types are ok")
		ctx := newMockContext(t)
		instance := ctx.verifier
		subject := testCredential(t)

		credentialType := ssi.MustParseURI("unknown type")
		subject.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI(), credentialType}

		err := instance.Verify(subject, true, false, nil)

		assert.EqualError(t, err, "unknown credential type")
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		subject := testCredential(t)
		subject.IssuanceDate.Add(-1 * time.Minute)

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(nil, errors.New("not found"))

		at := time.Now()
		err := instance.Validate(subject, &at)

		assert.EqualError(t, err, "unable to resolve valid signing key at given time: not found")
	})

	// Verify calls other verifiers / validators.
	// These test do not try to be complete, only test the calling of these validators and the error handling.

	t.Run("with signature check", func(t *testing.T) {
		vc := testCredential(t)

		t.Run("fails when key is not found", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			proofs, _ := vc.Proofs()
			ctx.docResolver.EXPECT().Resolve(did.MustParseDID(vc.Issuer.String()), gomock.Any()).Return(nil, nil, nil)
			ctx.keyResolver.EXPECT().ResolveSigningKey(proofs[0].VerificationMethod.String(), nil).Return(nil, vdrTypes.ErrKeyNotFound)

			validationErr := ctx.verifier.Verify(vc, true, true, nil)

			assert.EqualError(t, validationErr, "unable to resolve signing key: key not found in DID document")
		})

		t.Run("fails when controller or issuer is deactivated", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			ctx.docResolver.EXPECT().Resolve(did.MustParseDID(vc.Issuer.String()), gomock.Any()).Return(nil, nil, vdrTypes.ErrDeactivated)

			validationErr := ctx.verifier.Verify(vc, true, true, nil)

			assert.EqualError(t, validationErr, "could not validate issuer: the DID document has been deactivated")
		})
	})

	t.Run("invalid when revoked", func(t *testing.T) {
		vc := testCredential(t)
		ctx := newMockContext(t)
		ctx.store.EXPECT().GetRevocations(*vc.ID).Return([]*credential.Revocation{{}}, nil)
		sut := ctx.verifier
		validationErr := sut.Verify(vc, true, false, nil)
		assert.EqualError(t, validationErr, "credential is revoked")
	})

	t.Run("trust check", func(t *testing.T) {
		t.Run("trusted", func(t *testing.T) {
			vc := testCredential(t)
			vc.Proof[0] = map[string]interface{}{"jws": "foo"}
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			for _, vcType := range vc.Type {
				_ = ctx.trustConfig.AddTrust(vcType, vc.Issuer)
			}
			sut := ctx.verifier
			validationErr := sut.Verify(vc, false, false, nil)
			assert.NoError(t, validationErr)
		})
		t.Run("untrusted", func(t *testing.T) {
			vc := testCredential(t)
			vc.Proof[0] = map[string]interface{}{"jws": "foo"}
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			sut := ctx.verifier
			err := sut.Verify(vc, false, false, nil)
			assert.ErrorIs(t, err, types.ErrUntrusted)
		})
	})

	t.Run("no signature check", func(t *testing.T) {
		t.Run("ok, the vc is valid", func(t *testing.T) {
			vc := testCredential(t)
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			sut := ctx.verifier
			validationErr := sut.Verify(vc, true, false, nil)
			assert.NoError(t, validationErr,
				"expected no error when validating a valid vc")
		})

		t.Run("ok, with invalid signature", func(t *testing.T) {
			vc := testCredential(t)
			vc.Proof[0] = map[string]interface{}{"jws": "foo"}
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			sut := ctx.verifier
			validationErr := sut.Verify(vc, true, false, nil)
			assert.NoError(t, validationErr,
				"expected no error when validating a valid vc")
		})

		t.Run("failed validation", func(t *testing.T) {

			t.Run("missing required fields", func(t *testing.T) {
				vc := testCredential(t)
				// set the type to an empty array should make the credential invalid
				vc.Type = []ssi.URI{}
				ctx := newMockContext(t)
				sut := ctx.verifier
				validationErr := sut.Verify(vc, true, false, nil)
				assert.EqualError(t, validationErr, "validation failed: type 'VerifiableCredential' is required")
			})

			t.Run("credential not valid at given time", func(t *testing.T) {
				vc := testCredential(t)
				expirationTime := time.Now().Add(-10 * time.Hour)
				vc.ExpirationDate = &expirationTime
				ctx := newMockContext(t)
				ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
				sut := ctx.verifier
				validationErr := sut.Verify(vc, true, false, nil)
				assert.EqualError(t, validationErr, "credential not valid at given time")
			})

		})
	})
}

func Test_verifier_validateAtTime(t *testing.T) {
	var timeToCheck *time.Time
	t.Run("no time provided", func(t *testing.T) {
		timeToCheck = nil

		t.Run("credential is valid", func(t *testing.T) {
			sut := verifier{}
			credentialToTest := testCredential(t)
			valid := sut.validateAtTime(credentialToTest.IssuanceDate, credentialToTest.ExpirationDate, timeToCheck)
			assert.True(t, valid)
		})
	})

	t.Run("with a time provided", func(t *testing.T) {
		now := time.Now()
		t.Run("credential is valid at given time", func(t *testing.T) {
			timeToCheck = &now
			sut := verifier{}
			credentialToTest := testCredential(t)
			valid := sut.validateAtTime(credentialToTest.IssuanceDate, credentialToTest.ExpirationDate, timeToCheck)
			assert.True(t, valid)
		})

		t.Run("credential is invalid when timeAt is before issuance", func(t *testing.T) {
			beforeIssuance, err := time.Parse(time.RFC3339, "2006-10-05T14:33:12+02:00")
			require.NoError(t, err)
			timeToCheck = &beforeIssuance
			sut := verifier{}
			credentialToTest := testCredential(t)
			valid := sut.validateAtTime(credentialToTest.IssuanceDate, credentialToTest.ExpirationDate, timeToCheck)
			assert.False(t, valid)
		})

		t.Run("credential is invalid when timeAt is after expiration", func(t *testing.T) {
			expireTime, err := time.Parse(time.RFC3339, "2021-10-05T14:33:12+02:00")
			require.NoError(t, err)
			afterExpire := expireTime.Add(10 * time.Hour)
			timeToCheck = &afterExpire
			sut := verifier{}
			credentialToTest := testCredential(t)
			// Set expirationDate since the testCredential does not have one
			credentialToTest.ExpirationDate = &expireTime
			valid := sut.validateAtTime(credentialToTest.IssuanceDate, credentialToTest.ExpirationDate, timeToCheck)
			assert.False(t, valid)
		})

	})

}

func Test_verifier_CheckAndStoreRevocation(t *testing.T) {
	rawVerificationMethod, _ := os.ReadFile("../test/revocation-public.json")
	rawRevocation, _ := os.ReadFile("../test/ld-revocation.json")

	verificationMethod := did.VerificationMethod{}
	require.NoError(t, json.Unmarshal(rawVerificationMethod, &verificationMethod))
	key, err := verificationMethod.PublicKey()
	require.NoError(t, err)

	document := proof.SignedDocument{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &document))

	revocation := credential.Revocation{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it checks and stores a valid revocation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(key, nil)
		sut.store.EXPECT().StoreRevocation(revocation)
		err := sut.verifier.RegisterRevocation(revocation)
		assert.NoError(t, err)
	})

	t.Run("it fails when there are fields missing", func(t *testing.T) {
		sut := newMockContext(t)
		revocation := credential.Revocation{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))
		revocation.Subject = ssi.MustParseURI("")
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "validation failed: 'subject' is required and requires a valid fragment")
	})

	t.Run("it fails when the used verificationMethod is not from the issuer", func(t *testing.T) {
		sut := newMockContext(t)
		revocation := credential.Revocation{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))
		revocation.Proof.VerificationMethod = ssi.MustParseURI("did:nuts:123#abc")
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "verificationMethod should owned by the issuer")
	})

	t.Run("it fails when the revoked credential and revocation-issuer are not from the same identity", func(t *testing.T) {
		sut := newMockContext(t)
		revocation := credential.Revocation{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))
		revocation.Issuer = ssi.MustParseURI("did:nuts:123")
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "issuer of revocation is not the same as issuer of credential")
	})

	//t.Run("it fails when the proof has an invalid format", func(t *testing.T) {
	//	sut := newMockContext(t)
	//	revocation := credential.Revocation{}
	//	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))
	//	revocation.Proof = map[string]interface{}{"JWS": []string{"foo"}}
	//	err := sut.verifier.RegisterRevocation(revocation)
	//	assert.EqualError(t, err, "json: cannot unmarshal array into Go struct field JSONWebSignature2020Proof.proof.jws of type string")
	//})

	t.Run("it handles an unknown key error", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(nil, errors.New("unknown key"))
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to resolve key for revocation: unknown key")
	})

	t.Run("it handles an error from store operation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(key, nil)
		sut.store.EXPECT().StoreRevocation(revocation).Return(errors.New("storage error"))
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to store revocation: storage error")
	})

	t.Run("it handles an invalid signature error", func(t *testing.T) {
		sut := newMockContext(t)
		otherKey := crypto.NewTestKey("did:nuts:123#abc").Public()
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(otherKey, nil)
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to verify revocation signature: invalid proof signature: failed to verify signature using ecdsa")
	})
}

func TestVerifier_VerifyVP(t *testing.T) {
	rawVP := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "proof": {
    "created": "2022-03-07T15:17:05.447901+01:00",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..F49ecqz0jSnSQp4gSSOxVVdu7vN58oZv4uSC30DGGOVUeKHjHS5XUNvSr_r-egUCCouygCbzp5f9cMNbGQhNRw",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#abc-method-1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
      "company": {
        "city": "Hengelo",
        "name": "De beste zorg"
      },
      "id": "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW"
    },
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0",
    "issuanceDate": "2021-12-24T13:21:29.087205+01:00",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "proof": {
      "created": "2021-12-24T13:21:29.087205+01:00",
      "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..hPM2GLc1K9d2D8Sbve004x9SumjLqaXTjWhUhvqWRwxfRWlwfp5gHDUYuRoEjhCXfLt-_u-knChVmK980N3LBw",
      "proofPurpose": "assertionMethod",
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#abc-method-1"
    },
    "type": [
      "CompanyCredential",
      "VerifiableCredential"
    ]
  }
}`
	vp := vc.VerifiablePresentation{}
	_ = json.Unmarshal([]byte(rawVP), &vp)
	vpSignerKeyID := did.MustParseDIDURL(vp.Proof[0].(map[string]interface{})["verificationMethod"].(string))

	t.Run("ok - do not verify VCs", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveSigningKey(vpSignerKeyID.String(), validAt).Return(vdr.TestMethodDIDAPrivateKey().Public(), nil)

		vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

		assert.NoError(t, err)
		assert.Len(t, vcs, 1)
	})
	t.Run("ok - verify VCs (and verify trusted)", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveSigningKey(vpSignerKeyID.String(), validAt).Return(vdr.TestMethodDIDAPrivateKey().Public(), nil)

		mockVerifier := NewMockVerifier(ctx.ctrl)
		mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], false, true, validAt)

		vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, false, validAt)

		assert.NoError(t, err)
		assert.Len(t, vcs, 1)
	})
	t.Run("ok - verify VCs (do not need to be trusted)", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), validAt, vdrTypes.NutsSigningKeyType).Return(vdr.TestMethodDIDAPrivateKey().Public(), nil)

		mockVerifier := NewMockVerifier(ctx.ctrl)
		mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], true, true, validAt)

		vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, true, validAt)

		assert.NoError(t, err)
		assert.Len(t, vcs, 1)
	})
	t.Run("error - VP verification fails (not valid at time)", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt time.Time

		ctx := newMockContext(t)

		mockVerifier := NewMockVerifier(ctx.ctrl)

		vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, true, &validAt)

		assert.EqualError(t, err, "verification error: presentation not valid at given time")
		assert.Empty(t, vcs)
	})
	t.Run("error - VC verification fails", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		ctx.keyResolver.EXPECT().ResolveSigningKey(vpSignerKeyID.String(), validAt).Return(vdr.TestMethodDIDAPrivateKey().Public(), nil)

		mockVerifier := NewMockVerifier(ctx.ctrl)
		mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], false, true, validAt).Return(errors.New("invalid"))

		vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, false, validAt)

		assert.Error(t, err)
		assert.Empty(t, vcs)
	})
	t.Run("error - invalid signature", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		// Return incorrect key, causing signature verification failure
		ctx.keyResolver.EXPECT().ResolveSigningKey(vpSignerKeyID.String(), validAt).Return(vdr.TestMethodDIDBPrivateKey().Public(), nil)

		vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

		assert.EqualError(t, err, "verification error: invalid signature: invalid proof signature: failed to verify signature using ecdsa")
		assert.Empty(t, vcs)
	})
	t.Run("error - signing key unknown", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		var validAt *time.Time

		ctx := newMockContext(t)
		// Return incorrect key, causing signature verification failure
		ctx.keyResolver.EXPECT().ResolveSigningKey(vpSignerKeyID.String(), validAt).Return(nil, vdrTypes.ErrKeyNotFound)

		vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

		assert.ErrorIs(t, err, vdrTypes.ErrKeyNotFound)
		assert.Empty(t, vcs)
	})
	t.Run("error - invalid proof", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		vp.Proof = []interface{}{"invalid"}

		var validAt *time.Time

		ctx := newMockContext(t)

		vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

		assert.EqualError(t, err, "verification error: unsupported proof type: json: cannot unmarshal string into Go value of type proof.LDProof")
		assert.Empty(t, vcs)
	})
	t.Run("error - no proof", func(t *testing.T) {
		_ = json.Unmarshal([]byte(rawVP), &vp)

		vp.Proof = nil

		var validAt *time.Time

		ctx := newMockContext(t)

		vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

		assert.EqualError(t, err, "verification error: exactly 1 proof is expected")
		assert.Empty(t, vcs)
	})
}

func Test_verifier_IsRevoked(t *testing.T) {
	rawRevocation, _ := os.ReadFile("../test/ld-revocation.json")
	revocation := credential.Revocation{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it returns false if no revocation is found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return(nil, ErrNotFound)
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.NoError(t, err)
		assert.False(t, result)
	})
	t.Run("it returns true if a revocation is found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return([]*credential.Revocation{&revocation}, nil)
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.NoError(t, err)
		assert.True(t, result)
	})
	t.Run("it returns the error if the store returns an error", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return(nil, errors.New("foo"))
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.EqualError(t, err, "foo")
		assert.False(t, result)
	})
}

func TestVerifier_GetRevocation(t *testing.T) {
	rawRevocation, _ := os.ReadFile("../test/ld-revocation.json")
	revocation := credential.Revocation{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it returns nil, ErrNotFound if no revocation is found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return(nil, ErrNotFound)
		result, err := sut.verifier.GetRevocation(revocation.Subject)
		assert.Equal(t, ErrNotFound, err)
		assert.Nil(t, result)
	})
	t.Run("it returns the revocation if found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return([]*credential.Revocation{&revocation}, nil)
		result, err := sut.verifier.GetRevocation(revocation.Subject)
		assert.NoError(t, err)
		assert.Equal(t, revocation, *result)
	})
	t.Run("it returns the error if the store returns an error", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocations(revocation.Subject).Return(nil, errors.New("foo"))
		result, err := sut.verifier.GetRevocation(revocation.Subject)
		assert.EqualError(t, err, "foo")
		assert.Nil(t, result)
	})
}

func TestVerificationError_Is(t *testing.T) {
	assert.True(t, VerificationError{}.Is(VerificationError{}))
	assert.False(t, VerificationError{}.Is(errors.New("other")))
}

type mockContext struct {
	ctrl        *gomock.Controller
	docResolver *vdrTypes.MockDocResolver
	keyResolver *vdrTypes.MockKeyResolver
	store       *MockStore
	trustConfig *trust.Config
	verifier    *verifier
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	docResolver := vdrTypes.NewMockDocResolver(ctrl)
	keyResolver := vdrTypes.NewMockKeyResolver(ctrl)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	verifierStore := NewMockStore(ctrl)
	trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.yaml"))
	verifier := NewVerifier(verifierStore, docResolver, keyResolver, jsonldManager, trustConfig).(*verifier)
	return mockContext{
		ctrl:        ctrl,
		verifier:    verifier,
		docResolver: docResolver,
		keyResolver: keyResolver,
		store:       verifierStore,
		trustConfig: trustConfig,
	}
}
