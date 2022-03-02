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
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func testCredential(t *testing.T) vc.VerifiableCredential {
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("../test/vc.json")
	if !assert.NoError(t, json.Unmarshal(vcJSON, &subject)) {
		t.FailNow()
	}
	return subject
}

func Test_verifier_Validate(t *testing.T) {
	const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

	// load pub key
	pke := storage.PublicKeyEntry{}
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

	t.Run("error - invalid vm", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier

		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		_ = vc2.UnmarshalProofValue(&pr)
		u, _ := ssi.ParseURI(vc2.Issuer.String() + "2")
		pr[0].VerificationMethod = *u
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

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
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

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("error - no proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		vc2 := testCredential(t)
		vc2.Proof = []interface{}{}

		err := instance.Validate(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "unable to extract ldproof from signed document: json: cannot unmarshal array into Go value of type proof.LDProof")
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

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "invalid 'jws' value in proof")
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

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "illegal base64 data")
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

		credentialType, _ := ssi.ParseURI("unknown type")
		subject.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI(), *credentialType}

		err := instance.Verify(subject, true, false, nil)

		if !assert.Error(t, err) {
			return
		}
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
}

func Test_verifier_Verify(t *testing.T) {
	// Verify calls other verifiers / validators.
	// These test do not try to be complete, only test the calling of these validators and the error handling.

	t.Run("with signature check", func(t *testing.T) {
		t.Run("fails when key is not found", func(t *testing.T) {
			vc := testCredential(t)
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocation(*vc.ID).Return(nil, ErrNotFound)
			proofs, _ := vc.Proofs()
			ctx.keyResolver.EXPECT().ResolveSigningKey(proofs[0].VerificationMethod.String(), nil).Return(nil, types.ErrKeyNotFound)
			sut := ctx.verifier
			validationErr := sut.Verify(vc, true, true, nil)
			assert.EqualError(t, validationErr, "unable to resolve signing key: key not found in DID document")
		})
	})

	t.Run("invalid when revoked", func(t *testing.T) {
		vc := testCredential(t)
		ctx := newMockContext(t)
		ctx.store.EXPECT().GetRevocation(*vc.ID).Return(&credential.Revocation{}, nil)
		sut := ctx.verifier
		validationErr := sut.Verify(vc, true, false, nil)
		assert.EqualError(t, validationErr, "credential is revoked")
	})

	t.Run("no signature check", func(t *testing.T) {
		t.Run("ok, the vc is valid", func(t *testing.T) {
			vc := testCredential(t)
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocation(*vc.ID).Return(nil, ErrNotFound)
			sut := ctx.verifier
			validationErr := sut.Verify(vc, true, false, nil)
			assert.NoError(t, validationErr,
				"expected no error when validating a valid vc")
		})

		t.Run("ok, with invalid signature", func(t *testing.T) {
			vc := testCredential(t)
			vc.Proof[0] = map[string]interface{}{"jws": "foo"}
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocation(*vc.ID).Return(nil, ErrNotFound)
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
				ctx.store.EXPECT().GetRevocation(*vc.ID).Return(nil, ErrNotFound)
				sut := ctx.verifier
				validationErr := sut.Verify(vc, true, false, nil)
				assert.EqualError(t, validationErr, "credential not valid at given time")
			})

		})
	})
}

func Test_verifier_validateInTime(t *testing.T) {
	var timeToCheck *time.Time
	t.Run("no time provided", func(t *testing.T) {
		timeToCheck = nil

		t.Run("credential is valid", func(t *testing.T) {
			sut := verifier{}
			credentialToTest := testCredential(t)
			validationErr := sut.validateAtTime(credentialToTest, timeToCheck)
			assert.NoError(t, validationErr)
		})
	})

	t.Run("with a time provided", func(t *testing.T) {
		now := time.Now()
		t.Run("credential is valid at given time", func(t *testing.T) {
			timeToCheck = &now
			sut := verifier{}
			credentialToTest := testCredential(t)
			validationErr := sut.validateAtTime(credentialToTest, timeToCheck)
			assert.NoError(t, validationErr)
		})

		t.Run("credential is invalid when timeAt is before issuance", func(t *testing.T) {
			beforeIssuance, err := time.Parse(time.RFC3339, "2006-10-05T14:33:12+02:00")
			if !assert.NoError(t, err) {
				return
			}
			timeToCheck = &beforeIssuance
			sut := verifier{}
			credentialToTest := testCredential(t)
			validationErr := sut.validateAtTime(credentialToTest, timeToCheck)
			assert.EqualError(t, validationErr, "credential not valid at given time")
		})

		t.Run("credential is invalid when timeAt is after expiration", func(t *testing.T) {
			expireTime, err := time.Parse(time.RFC3339, "2021-10-05T14:33:12+02:00")
			if !assert.NoError(t, err) {
				return
			}
			afterExpire := expireTime.Add(10 * time.Hour)
			timeToCheck = &afterExpire
			sut := verifier{}
			credentialToTest := testCredential(t)
			// Set expirationDate since the testCredential does not have one
			credentialToTest.ExpirationDate = &expireTime
			validationErr := sut.validateAtTime(credentialToTest, timeToCheck)
			assert.EqualError(t, validationErr, "credential not valid at given time")
		})

	})

}

func Test_verifier_CheckAndStoreRevocation(t *testing.T) {
	rawVerificationMethod, _ := os.ReadFile("../test/revocation-public.json")
	rawRevocation, _ := os.ReadFile("../test/ld-revocation.json")

	verificationMethod := did.VerificationMethod{}
	if !assert.NoError(t, json.Unmarshal(rawVerificationMethod, &verificationMethod)) {
		return
	}
	key, err := verificationMethod.PublicKey()
	if !assert.NoError(t, err) {
		return
	}

	document := proof.SignedDocument{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &document))

	revocation := credential.Revocation{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it checks and stores a valid revocation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(key, nil)
		sut.store.EXPECT().StoreRevocation(revocation)
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.NoError(t, err)
	})

	t.Run("it fails when there are fields missing", func(t *testing.T) {
		sut := newMockContext(t)
		document := proof.SignedDocument{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &document))
		document["subject"] = ""
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "validation failed: 'subject' is required and requires a valid fragment")
	})

	t.Run("it fails when the used verificationMethod is not from the issuer", func(t *testing.T) {
		sut := newMockContext(t)
		document := proof.SignedDocument{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &document))
		proof := document["proof"].(map[string]interface{})
		proof["verificationMethod"] = "did:nuts:123#abc"
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "verificationMethod should owned by the issuer")
	})

	t.Run("it fails when the revoked credential and revocation-issuer are not from the same identity", func(t *testing.T) {
		sut := newMockContext(t)
		document := proof.SignedDocument{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &document))
		document["issuer"] = "did:nuts:123"
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "issuer of revocation is not the same as issuer of credential")
	})

	t.Run("it fails when the proof has an invalid format", func(t *testing.T) {
		sut := newMockContext(t)
		document := proof.SignedDocument{}
		assert.NoError(t, json.Unmarshal(rawRevocation, &document))
		document["proof"] = map[string]interface{}{"JWS": []string{"foo"}}
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "json: cannot unmarshal array into Go struct field JSONWebSignature2020Proof.proof.jws of type string")
	})

	t.Run("it handles an unknown key error", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(nil, errors.New("unknown key"))
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "unable to resolve key for revocation: unknown key")
	})

	t.Run("it handles an error from store operation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(key, nil)
		sut.store.EXPECT().StoreRevocation(revocation).Return(errors.New("storage error"))
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "unable to store revocation: storage error")
	})

	t.Run("it handles an invalid signature error", func(t *testing.T) {
		sut := newMockContext(t)
		otherKey := crypto.NewTestKey("did:nuts:123#abc").Public()
		sut.keyResolver.EXPECT().ResolveSigningKey(revocation.Proof.VerificationMethod.String(), &revocation.Date).Return(otherKey, nil)
		err := sut.verifier.CheckAndStoreRevocation(document)
		assert.EqualError(t, err, "unable to verify revocation signature: invalid proof signature: failed to verify signature using ecdsa")
	})
}

func Test_verifier_IsRevoked(t *testing.T) {
	rawRevocation, _ := os.ReadFile("../test/ld-revocation.json")
	revocation := credential.Revocation{}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it returns false if no revocation is found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocation(revocation.Subject).Return(nil, ErrNotFound)
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.NoError(t, err)
		assert.False(t, result)
	})
	t.Run("it returns true if a revocation is found", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocation(revocation.Subject).Return(&revocation, nil)
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.NoError(t, err)
		assert.True(t, result)
	})
	t.Run("it returns the error if the store returns an error", func(t *testing.T) {
		sut := newMockContext(t)
		sut.store.EXPECT().GetRevocation(revocation.Subject).Return(nil, errors.New("foo"))
		result, err := sut.verifier.IsRevoked(revocation.Subject)
		assert.EqualError(t, err, "foo")
		assert.False(t, result)
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	keyResolver *types.MockKeyResolver
	store       *MockStore
	verifier    Verifier
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	keyResolver := types.NewMockKeyResolver(ctrl)
	contextLoader, err := signature.NewContextLoader(false)
	verifierStore := NewMockStore(ctrl)
	assert.NoError(t, err)
	verifier := NewVerifier(verifierStore, keyResolver, contextLoader)
	return mockContext{
		ctrl:        ctrl,
		verifier:    verifier,
		keyResolver: keyResolver,
		store:       verifierStore,
	}
}
