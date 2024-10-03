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
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/revocation"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func testCredential(t *testing.T) vc.VerifiableCredential {
	subject := test.ValidNutsOrganizationCredential(t)
	return subject
}

func TestVerifier_Verify(t *testing.T) {
	const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

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

		ctx.keyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(nil, errors.New("not found"))

		at := time.Now()
		err := instance.VerifySignature(subject, &at)

		assert.EqualError(t, err, "unable to resolve valid signing key: not found")
	})

	// Verify calls other verifiers / validators.
	// These test do not try to be complete, only test the calling of these validators and the error handling.

	t.Run("with signature check", func(t *testing.T) {
		vc := testCredential(t)

		t.Run("fails when key is not found", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			proofs, _ := vc.Proofs()
			ctx.didResolver.EXPECT().Resolve(did.MustParseDID(vc.Issuer.String()), gomock.Any()).Return(nil, nil, nil)
			ctx.keyResolver.EXPECT().ResolveKeyByID(proofs[0].VerificationMethod.String(), gomock.Any(), resolver.NutsSigningKeyType).Return(nil, resolver.ErrKeyNotFound)

			validationErr := ctx.verifier.Verify(vc, true, true, nil)

			assert.EqualError(t, validationErr, "unable to resolve valid signing key: key not found in DID document")
		})

		t.Run("fails when controller or issuer is deactivated", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.store.EXPECT().GetRevocations(*vc.ID).Return(nil, ErrNotFound)
			ctx.didResolver.EXPECT().Resolve(did.MustParseDID(vc.Issuer.String()), gomock.Any()).Return(nil, nil, resolver.ErrDeactivated)

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

	t.Run("validate credentialStatus", func(t *testing.T) {
		// make StatusList2021Credential with a revocation bit set
		statusListCred := test.ValidStatusList2021Credential(t)
		statusListCredBytes, err := json.Marshal(statusListCred)
		require.NoError(t, err)
		statusListIndex := 1 // bit 1 is set in slCred

		// Test server
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Write(statusListCredBytes)
		}))

		// statusListEntry for credentialToValidate without statusListIndex
		slEntry := revocation.StatusList2021Entry{
			ID:                   "https://example-com/credentials/status/3#statusListIndex",
			Type:                 revocation.StatusList2021EntryType,
			StatusPurpose:        "revocation",
			StatusListCredential: ts.URL,
		}

		// mock context
		http.DefaultClient = ts.Client() // newMockContext sets credentialStatus.client to http.DefaultClient
		ctx := newMockContext(t)
		ctx.store.EXPECT().GetRevocations(gomock.Any()).Return([]*credential.Revocation{{}}, ErrNotFound).AnyTimes()
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		ctx.verifier.credentialStatus = revocation.NewStatusList2021(db, ts.Client(), "https://example.com")
		ctx.verifier.credentialStatus.(*revocation.StatusList2021).VerifySignature = func(_ vc.VerifiableCredential, _ *time.Time) error { return nil } // don't check signatures on 'downloaded' StatusList2021Credentials
		ctx.verifier.credentialStatus.(*revocation.StatusList2021).Sign = func(_ context.Context, unsignedCredential vc.VerifiableCredential, _ string) (*vc.VerifiableCredential, error) {
			bs, err := json.Marshal(unsignedCredential)
			require.NoError(t, err)
			return &unsignedCredential, json.Unmarshal(bs, &unsignedCredential)
		}
		ctx.verifier.credentialStatus.(*revocation.StatusList2021).ResolveKey = func(issuerDID did.DID, _ *time.Time, _ resolver.RelationType) (string, crypto.PublicKey, error) {
			return "", nil, nil
		} // ctx.verifier.credentialStatus.Sign ignores the key

		cred := test.ValidNutsOrganizationCredential(t)
		cred.Context = append(cred.Context, ssi.MustParseURI(jsonld.W3cStatusList2021Context))

		t.Run("not revoked", func(t *testing.T) {
			slEntry.StatusListIndex = strconv.Itoa(statusListIndex + 1)
			cred.CredentialStatus = []any{slEntry}

			validationErr := ctx.verifier.Verify(cred, true, false, nil)

			assert.NoError(t, validationErr)
		})
		t.Run("is revoked", func(t *testing.T) {
			didAlice := did.MustParseDID("did:web:example.com:iam:alice")
			storage.AddDIDtoSQLDB(t, db, didAlice)
			entry, err := ctx.verifier.credentialStatus.(*revocation.StatusList2021).Entry(context.Background(), didAlice, revocation.StatusPurposeRevocation)
			require.NoError(t, err)
			require.NoError(t, ctx.verifier.credentialStatus.(*revocation.StatusList2021).Revoke(context.Background(), ssi.URI{}, *entry))
			cred := test.ValidNutsOrganizationCredential(t)
			credentialID := didAlice.URI()
			credentialID.Fragment = "123"
			cred.ID = &credentialID
			cred.Issuer = didAlice.URI()
			cred.CredentialStatus = []any{entry}
			cred.Context = append(cred.Context, revocation.StatusList2021ContextURI)

			validationErr := ctx.verifier.Verify(cred, true, false, nil)

			assert.ErrorIs(t, validationErr, types.ErrRevoked)
		})
		t.Run("ignore other purpose", func(t *testing.T) {
			slEntry.StatusListIndex = strconv.Itoa(statusListIndex)
			slEntry.StatusPurpose = "suspension"
			cred.CredentialStatus = []any{slEntry}

			validationErr := ctx.verifier.Verify(cred, true, false, nil)

			assert.NoError(t, validationErr)
		})
		t.Run("don't fail if error is other than types.ErrRevoked", func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(400)
			}))
			slEntry := revocation.StatusList2021Entry{
				ID:                   "not relevant",
				Type:                 revocation.StatusList2021EntryType,
				StatusPurpose:        "revocation",
				StatusListIndex:      "1",
				StatusListCredential: ts.URL, //
			}
			cred.CredentialStatus = []any{slEntry}

			validationErr := ctx.verifier.Verify(cred, true, false, nil)

			assert.NoError(t, validationErr)
		})
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

	t.Run("incorrect number of types", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.verifier
		testCred := testCredential(t)
		testCred.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("a"), ssi.MustParseURI("b")}

		err := instance.Verify(testCred, true, false, nil)

		assert.EqualError(t, err, "verifiable credential must list at most 2 types")
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
	metadata := resolver.ResolveMetadata{ResolveTime: &revocation.Date}
	assert.NoError(t, json.Unmarshal(rawRevocation, &revocation))

	t.Run("it checks and stores a valid revocation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveKeyByID(revocation.Proof.VerificationMethod.String(), &metadata, resolver.NutsSigningKeyType).Return(key, nil)
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
		assert.ErrorIs(t, err, errVerificationMethodNotOfIssuer)
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
		sut.keyResolver.EXPECT().ResolveKeyByID(revocation.Proof.VerificationMethod.String(), &metadata, resolver.NutsSigningKeyType).Return(nil, errors.New("unknown key"))
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to resolve key for revocation: unknown key")
	})

	t.Run("it handles an error from store operation", func(t *testing.T) {
		sut := newMockContext(t)
		sut.keyResolver.EXPECT().ResolveKeyByID(revocation.Proof.VerificationMethod.String(), &metadata, resolver.NutsSigningKeyType).Return(key, nil)
		sut.store.EXPECT().StoreRevocation(revocation).Return(errors.New("storage error"))
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to store revocation: storage error")
	})

	t.Run("it handles an invalid signature error", func(t *testing.T) {
		sut := newMockContext(t)
		otherKey, _ := spi.GenerateKeyPair()
		sut.keyResolver.EXPECT().ResolveKeyByID(revocation.Proof.VerificationMethod.String(), &metadata, resolver.NutsSigningKeyType).Return(otherKey, nil)
		err := sut.verifier.RegisterRevocation(revocation)
		assert.EqualError(t, err, "unable to verify revocation signature: invalid proof signature: failed to verify signature using ecdsa")
	})
}

func TestVerifier_VerifyVP(t *testing.T) {
	t.Run("JWT", func(t *testing.T) {
		subjectDID := did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")
		keyID := subjectDID.String() + "#abc-method-1"
		key, err := jwk.ParseKey([]byte(`{
 "crv": "P-256",
 "d": "mvipTdytRXwTTY_6wJl5Cwj0YQ4-QdJK-fEC8DzL9_M",
 "kty": "EC",
 "x": "8WvKOR7ZpOSfNxT20Qig8DuVY7QAwx6Qe4NNejTN3po",
 "y": "UYZoXK13bedMDHvsrGskxihDuWIXgGBdQfTvjyQlCDE"
}`))
		require.NoError(t, err)
		var publicKey crypto.PublicKey
		require.NoError(t, key.Raw(&publicKey))

		const rawVP = `eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpudXRzOkd2a3p4c2V6SHZFYzhuR2hnejZYbzNqYnFrSHdzd0xtV3czQ1l0Q203aEFXI2FiYy1tZXRob2QtMSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTc2OTY3NDEsImlzcyI6ImRpZDpudXRzOkd2a3p4c2V6SHZFYzhuR2hnejZYbzNqYnFrSHdzd0xtV3czQ1l0Q203aEFXIiwibmJmIjoxNjk3NjEwMzQxLCJzdWIiOiJkaWQ6bnV0czpHdmt6eHNlekh2RWM4bkdoZ3o2WG8zamJxa0h3c3dMbVd3M0NZdENtN2hBVyIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL251dHMubmwvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL2xkcy1qd3MyMDIwL2NvbnRleHRzL2xkcy1qd3MyMDIwLXYxLmpzb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY29tcGFueSI6eyJjaXR5IjoiSGVuZ2VsbyIsIm5hbWUiOiJEZSBiZXN0ZSB6b3JnIn0sImlkIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcifSwiaWQiOiJkaWQ6bnV0czo0dHpNYVdmcGl6VktlQThmc2NDM0pUZFdCYzNhc1VXV01qNWhVRkhkV1gzSCNmNDNiZWY0Zi0xYTc5LTQzNjQtOTJmMy0zZmM3NDNmYTlmMTkiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTEyLTI0VDEzOjIxOjI5LjA4NzIwNSswMTowMCIsImlzc3VlciI6ImRpZDpudXRzOjR0ek1hV2ZwaXpWS2VBOGZzY0MzSlRkV0JjM2FzVVdXTWo1aFVGSGRXWDNIIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjEtMTItMjRUMTM6MjE6MjkuMDg3MjA1KzAxOjAwIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLmhQTTJHTGMxSzlkMkQ4U2J2ZTAwNHg5U3VtakxxYVhUaldoVWh2cVdSd3hmUldsd2ZwNWdIRFVZdVJvRWpoQ1hmTHQtX3Uta25DaFZtSzk4ME4zTEJ3IiwicHJvb2ZQdXJwb3NlIjoiTnV0c1NpZ25pbmdLZXlUeXBlIiwidHlwZSI6Ikpzb25XZWJTaWduYXR1cmUyMDIwIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcjYWJjLW1ldGhvZC0xIn0sInR5cGUiOlsiQ29tcGFueUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfX19.v3beJvGa3HeImU3VLvsrZjnHs0krKPaCdTEh-qHS7j26LIQYcMHhrLkIexrpPO5z0TKSDnKq5Jl10SWaJpLRIA`

		presentation, err := vc.ParseVerifiablePresentation(rawVP)
		require.NoError(t, err)

		t.Run("ok", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(keyID, gomock.Any(), resolver.NutsSigningKeyType).Return(publicKey, nil)

			validAt := time.Date(2023, 10, 18, 12, 0, 0, 0, time.UTC)
			vcs, err := ctx.verifier.VerifyVP(*presentation, false, false, &validAt)

			assert.NoError(t, err)
			assert.Len(t, vcs, 1)
		})
		t.Run("ok - no credentials", func(t *testing.T) {
			ctx := newMockContext(t)
			presentation, key := test.CreateJWTPresentation(t, subjectDID, nil)
			ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), resolver.NutsSigningKeyType).Return(key, nil)

			vcs, err := ctx.verifier.VerifyVP(presentation, false, false, nil)

			assert.NoError(t, err)
			assert.Empty(t, vcs)
		})
		t.Run("self-asserted VCs", func(t *testing.T) {
			// Test support for https://www.w3.org/TR/vc-data-model-2.0/#presentations-including-holder-claims
			// Self-asserted VCs don't need to contain a proof, but the VC credentialSubject.id must equal the VC issuer,
			// and the VC issuer must equal the VP holder.
			selfAssertedCredential := vc.VerifiableCredential{
				Issuer: subjectDID.URI(),
				CredentialSubject: []interface{}{
					map[string]interface{}{
						"id": subjectDID.String(),
					},
				},
			}
			t.Run("ok - credential has no own proof", func(t *testing.T) {
				vp, key := test.CreateJWTPresentation(t, subjectDID, func(token jwt.Token) {
					vpRaw, _ := token.Get("vp")
					castVP := vpRaw.(vc.VerifiablePresentation)
					castVP.Holder, _ = ssi.ParseURI(subjectDID.String())
					_ = token.Set("vp", castVP)
				}, selfAssertedCredential)
				ctx := newMockContext(t)
				ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), gomock.Any()).Return(key, nil)

				mockVerifier := NewMockVerifier(ctx.ctrl)
				mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], true, false, nil)

				vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, true, nil)

				assert.NoError(t, err)
				assert.Len(t, vcs, 1)
			})
		})
		t.Run("holder != subject", func(t *testing.T) {
			presentationWithHolder := *presentation
			presentationWithHolder.Holder, _ = ssi.ParseURI("other")

			ctx := newMockContext(t)

			mockVerifier := NewMockVerifier(ctx.ctrl)

			vcs, err := ctx.verifier.doVerifyVP(mockVerifier, presentationWithHolder, true, true, nil)

			assert.EqualError(t, err, "verification error: presentation holder must equal credential subject")
			assert.Empty(t, vcs)
		})
		t.Run("JWT expired", func(t *testing.T) {
			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(keyID, gomock.Any(), resolver.NutsSigningKeyType).Return(publicKey, nil)

			validAt := time.Date(2023, 10, 21, 12, 0, 0, 0, time.UTC)
			vcs, err := ctx.verifier.VerifyVP(*presentation, false, false, &validAt)

			assert.EqualError(t, err, "unable to validate JWT signature: \"exp\" not satisfied")
			assert.Empty(t, vcs)
		})
		t.Run("VP signer != VC credentialSubject.id", func(t *testing.T) {
			// This VP was produced by a Sphereon Wallet, using did:key. The signer of the VP is a did:key,
			// but the holder of the contained credential is a did:jwt. So the presenter is not the holder. Weird?
			const rawVP = `eyJraWQiOiJkaWQ6a2V5Ono2TWtzRXl4NmQ1cEIxZWtvYVZtYUdzaWJiY1lIRTlWeHg3VjEzUFNxUHd4WVJ6TCN6Nk1rc0V5eDZkNXBCMWVrb2FWbWFHc2liYmNZSEU5Vnh4N1YxM1BTcVB3eFlSekwiLCJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi9wcmVzZW50YXRpb24tZXhjaGFuZ2Uvc3VibWlzc2lvbi92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJQcmVzZW50YXRpb25TdWJtaXNzaW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTJPVFl6TURFM01EZ3NJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pIZFdWemRFTnlaV1JsYm5ScFlXd2lYU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVptbHljM1JPWVcxbElqb2lTR1ZzYkc4aUxDSnNZWE4wVG1GdFpTSTZJbE53YUdWeVpXOXVJaXdpWlcxaGFXd2lPaUp6Y0dobGNtVnZia0JsZUdGdGNHeGxMbU52YlNJc0luUjVjR1VpT2lKVGNHaGxjbVZ2YmlCSGRXVnpkQ0lzSW1sa0lqb2laR2xrT21wM2F6cGxlVXBvWWtkamFVOXBTa1pWZWtreFRtdHphVXhEU2pGak1sVnBUMmxLZW1GWFkybE1RMHB5WkVocmFVOXBTa1pSZVVselNXMU9lV1JwU1RaSmJrNXNXVE5CZVU1VVduSk5VMGx6U1c1bmFVOXBTbXBOVm1SWlkzcGtXRTB5TVRWak1sWldXbXMxUTJOWVRqUmFSa0pZVVd0c1NHRkZkR3RPUmxJMlRVVjRVMHhWV25GUFJWcE9WMWRGZDBscGQybGxVMGsyU1d4a2RHRXdUbGxrVkVZelpWaHdZVm93WkU5T01WWTBWRzFHZDJOSVJuVlVNVVpvVkRKMFdFMXJUbTVVTVU1MVZESTVOVlJWYkZWa1YwMXBabEVpZlgwc0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pIZFdWemRFTnlaV1JsYm5ScFlXd2lYU3dpWlhod2FYSmhkR2x2YmtSaGRHVWlPaUl5TURJekxURXdMVEF6VkRBeU9qVTFPakE0TGpFek0xb2lMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKbWFYSnpkRTVoYldVaU9pSklaV3hzYnlJc0lteGhjM1JPWVcxbElqb2lVM0JvWlhKbGIyNGlMQ0psYldGcGJDSTZJbk53YUdWeVpXOXVRR1Y0WVcxd2JHVXVZMjl0SWl3aWRIbHdaU0k2SWxOd2FHVnlaVzl1SUVkMVpYTjBJaXdpYVdRaU9pSmthV1E2YW5kck9tVjVTbWhpUjJOcFQybEtSbFY2U1RGT2EzTnBURU5LTVdNeVZXbFBhVXA2WVZkamFVeERTbkprU0d0cFQybEtSbEY1U1hOSmJVNTVaR2xKTmtsdVRteFpNMEY1VGxSYWNrMVRTWE5KYm1kcFQybEthazFXWkZsamVtUllUVEl4TldNeVZsWmFhelZEWTFoT05GcEdRbGhSYTJ4SVlVVjBhMDVHVWpaTlJYaFRURlZhY1U5RldrNVhWMFYzU1dsM2FXVlRTVFpKYkdSMFlUQk9XV1JVUmpObFdIQmhXakJrVDA0eFZqUlViVVozWTBoR2RWUXhSbWhVTW5SWVRXdE9ibFF4VG5WVU1qazFWRlZzVldSWFRXbG1VU0o5TENKcGMzTjFaWElpT2lKa2FXUTZhbmRyT21WNVNtaGlSMk5wVDJsS1JsVjZTVEZPYVVselNXNVdlbHBUU1RaSmJrNXdXbmxKYzBsdGREQmxVMGsyU1d0V1JFbHBkMmxaTTBveVNXcHZhVlZETUhsT1ZGbHBURU5LTkVscWIybFdSV041VTBSS05FMXRVbGhYUlRSNlpGVk9lRmR1UW5oU2FrWTFZekJHVVZWV1drVlRhMVpQV0RCbmRGRXdNVEJaYldSeFdXa3hUMXA1U1hOSmJtdHBUMmxKTlZSVWFFOWxSMUYzVlVVMGVVMXJNRFZpUmtKRlpVZFNkMUpJUW5aV1JYZzJUVlJXTTFwdWJHRlRiazB5VjIxb1RGTldWa3ROZWswMFNXNHdJaXdpYVhOemRXRnVZMlZFWVhSbElqb2lNakF5TXkwd09TMHlPVlF4TWpvek1Ub3dPQzR4TXpOYUlpd2ljM1ZpSWpvaVpHbGtPbXAzYXpwbGVVcG9Za2RqYVU5cFNrWlZla2t4VG10emFVeERTakZqTWxWcFQybEtlbUZYWTJsTVEwcHlaRWhyYVU5cFNrWlJlVWx6U1cxT2VXUnBTVFpKYms1c1dUTkJlVTVVV25KTlUwbHpTVzVuYVU5cFNtcE5WbVJaWTNwa1dFMHlNVFZqTWxaV1dtczFRMk5ZVGpSYVJrSllVV3RzU0dGRmRHdE9SbEkyVFVWNFUweFZXbkZQUlZwT1YxZEZkMGxwZDJsbFUwazJTV3hrZEdFd1RsbGtWRVl6WlZod1lWb3daRTlPTVZZMFZHMUdkMk5JUm5WVU1VWm9WREowV0UxclRtNVVNVTUxVkRJNU5WUlZiRlZrVjAxcFpsRWlMQ0p1WW1ZaU9qRTJPVFU1T1RBMk5qZ3NJbWx6Y3lJNkltUnBaRHBxZDJzNlpYbEthR0pIWTJsUGFVcEdWWHBKTVU1cFNYTkpibFo2V2xOSk5rbHVUbkJhZVVselNXMTBNR1ZUU1RaSmExWkVTV2wzYVZrelNqSkphbTlwVlVNd2VVNVVXV2xNUTBvMFNXcHZhVlpGWTNsVFJFbzBUVzFTV0ZkRk5IcGtWVTU0VjI1Q2VGSnFSalZqTUVaUlZWWmFSVk5yVms5WU1HZDBVVEF4TUZsdFpIRlphVEZQV25sSmMwbHVhMmxQYVVrMVZGUm9UMlZIVVhkVlJUUjVUV3N3TldKR1FrVmxSMUozVWtoQ2RsWkZlRFpOVkZZeldtNXNZVk51VFRKWGJXaE1VMVpXUzAxNlRUUkpiakFpZlEud2RodExYRTRqVTFDLTNZQkJwUDktcUUteWgxeE9aNmxCTEotMGU1X1NhN2ZuclVIY0FhVTFuM2tOMkNlQ3lUVmp0bTFVeTNUbDZSelVPTTZNalAzdlEiXX0sInByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoidG9DdGp5Y0V3QlZCWVBsbktBQTZGIiwiZGVmaW5pdGlvbl9pZCI6InNwaGVyZW9uIiwiZGVzY3JpcHRvcl9tYXAiOlt7ImlkIjoiNGNlN2FmZjEtMDIzNC00ZjM1LTlkMjEtMjUxNjY4YTYwOTUwIiwiZm9ybWF0Ijoiand0X3ZjIiwicGF0aCI6IiQudmVyaWZpYWJsZUNyZWRlbnRpYWxbMF0ifV19LCJuYmYiOjE2OTU5OTU2MzYsImlzcyI6ImRpZDprZXk6ejZNa3NFeXg2ZDVwQjFla29hVm1hR3NpYmJjWUhFOVZ4eDdWMTNQU3FQd3hZUnpMIn0.w3guHX-pmxJGGn5dGSSIKSba9xywnOutDk-l3tc_bpgHEOSbcR1mmmCqX5sSlZM_G0hgAbgpIv_YYI5iQNIfCw`
			const keyID = "did:key:z6MksEyx6d5pB1ekoaVmaGsibbcYHE9Vxx7V13PSqPwxYRzL#z6MksEyx6d5pB1ekoaVmaGsibbcYHE9Vxx7V13PSqPwxYRzL"
			keyAsJWK, err := jwk.ParseKey([]byte(`{
		"kty": "OKP",
		"crv": "Ed25519",
		"x": "vgLDESnU0TIlW-PmajyrvSlk9VysAsRkSYiEPBELj-U"
		}`))
			require.NoError(t, err)
			require.NoError(t, keyAsJWK.Set("kid", keyID))

			presentation, err := vc.ParseVerifiablePresentation(rawVP)
			require.NoError(t, err)
			ctx := newMockContext(t)

			vcs, err := ctx.verifier.VerifyVP(*presentation, false, false, nil)

			assert.EqualError(t, err, "verification error: credential(s) must be presented by subject")
			assert.Empty(t, vcs)
		})
	})
	t.Run("JSONLD", func(t *testing.T) {
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

		t.Run("ok - no credentials in VP", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			var validAt *time.Time
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDAPrivateKey().PublicKey, nil)

			vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

			assert.NoError(t, err)
			assert.Len(t, vcs, 1)
		})
		t.Run("ok - verify VCs (and verify trusted)", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			var validAt *time.Time
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDAPrivateKey().PublicKey, nil)

			mockVerifier := NewMockVerifier(ctx.ctrl)
			mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], false, true, validAt)

			vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, false, validAt)

			assert.NoError(t, err)
			assert.Len(t, vcs, 1)
		})
		t.Run("ok - verify VCs (do not need to be trusted)", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			var validAt *time.Time
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDAPrivateKey().PublicKey, nil)

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
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDAPrivateKey().PublicKey, nil)

			mockVerifier := NewMockVerifier(ctx.ctrl)
			mockVerifier.EXPECT().Verify(vp.VerifiableCredential[0], false, true, validAt).Return(errors.New("invalid"))

			vcs, err := ctx.verifier.doVerifyVP(mockVerifier, vp, true, false, validAt)

			assert.Error(t, err)
			assert.Empty(t, vcs)
		})
		t.Run("error - invalid signature", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			var validAt *time.Time
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			// Return incorrect key, causing signature verification failure
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDBPrivateKey().PublicKey, nil)

			vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

			assert.EqualError(t, err, "verification error: invalid signature: invalid proof signature: failed to verify signature using ecdsa")
			assert.Empty(t, vcs)
		})
		t.Run("error - signing key unknown", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			var validAt *time.Time
			metadata := resolver.ResolveMetadata{ResolveTime: validAt}

			ctx := newMockContext(t)
			// Return incorrect key, causing signature verification failure
			ctx.keyResolver.EXPECT().ResolveKeyByID(vpSignerKeyID.String(), &metadata, resolver.NutsSigningKeyType).Return(nil, resolver.ErrKeyNotFound)

			vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

			assert.ErrorIs(t, err, resolver.ErrKeyNotFound)
			assert.Empty(t, vcs)
		})
		t.Run("error - invalid proof", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			vp.Proof = []interface{}{"invalid"}

			var validAt *time.Time

			ctx := newMockContext(t)

			vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

			assert.EqualError(t, err, "verification error: presenter is credential subject: invalid LD-proof for presentation: json: cannot unmarshal string into Go value of type proof.LDProof")
			assert.Empty(t, vcs)
		})
		t.Run("error - no proof", func(t *testing.T) {
			_ = json.Unmarshal([]byte(rawVP), &vp)

			vp.Proof = nil

			var validAt *time.Time

			ctx := newMockContext(t)

			vcs, err := ctx.verifier.VerifyVP(vp, false, false, validAt)

			assert.EqualError(t, err, "verification error: presenter is credential subject: presentation should have exactly 1 proof, got 0")
			assert.Empty(t, vcs)
		})
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
	didResolver *resolver.MockDIDResolver
	keyResolver *resolver.MockKeyResolver
	store       *MockStore
	trustConfig *trust.Config
	verifier    *verifier
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	verifierStore := NewMockStore(ctrl)
	trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.yaml"))
	db := orm.NewTestDatabase(t)
	verifier := NewVerifier(verifierStore, didResolver, keyResolver, jsonldManager, trustConfig, revocation.NewStatusList2021(db, nil, "")).(*verifier)
	return mockContext{
		ctrl:        ctrl,
		verifier:    verifier,
		didResolver: didResolver,
		keyResolver: keyResolver,
		store:       verifierStore,
		trustConfig: trustConfig,
	}
}
