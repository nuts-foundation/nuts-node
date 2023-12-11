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

package holder

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var testDID = vdr.TestDIDA

func TestWallet_BuildPresentation(t *testing.T) {
	var kid = vdr.TestMethodDIDA.String()
	testCredential := createCredential(kid)
	key := vdr.TestMethodDIDAPrivateKey()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	testDID := vdr.TestDIDA
	ctx := audit.TestContext()

	keyStorage := crypto.NewMemoryStorage()
	_ = keyStorage.SavePrivateKey(ctx, key.KID(), key.PrivateKey)
	keyStore := crypto.NewTestCryptoInstance(keyStorage)

	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("is default", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, PresentationOptions{}, &testDID, false)

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
		})
		t.Run("ok - one VC", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, PresentationOptions{Format: JSONLDPresentationFormat}, &testDID, false)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.ID, "id must be set")
			assert.Equal(t, testDID, did.MustParseDIDURL(result.ID.String()).DID, "id must be the DID of the holder")
			assert.NotEmpty(t, result.ID.Fragment, "id must have a fragment")
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
			ldProof, err := credential.ParseLDProof(*result)
			require.NoError(t, err)
			assert.Empty(t, ldProof.Nonce)
		})
		t.Run("ok - custom options", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			specialType := ssi.MustParseURI("SpecialPresentation")
			domain := "https://example.com"
			nonce := "the-nonce"
			options := PresentationOptions{
				AdditionalContexts: []ssi.URI{credential.NutsV1ContextURI},
				AdditionalTypes:    []ssi.URI{specialType},
				ProofOptions: proof.ProofOptions{
					ProofPurpose: "authentication",
					Domain:       &domain,
					Nonce:        &nonce,
				},
				Format: JSONLDPresentationFormat,
			}
			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, false)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.IsType(specialType))
			assert.True(t, result.ContainsContext(credential.NutsV1ContextURI))
			var proofs []proof.LDProof
			require.NoError(t, result.UnmarshalProofValue(&proofs))
			require.Len(t, proofs, 1)
			assert.Equal(t, "authentication", proofs[0].ProofPurpose)
			assert.Equal(t, "https://example.com", *proofs[0].Domain)
			assert.Equal(t, nonce, *proofs[0].Nonce)
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
		})
		t.Run("ok - multiple VCs", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDA.URI(), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential, testCredential}, PresentationOptions{Format: JSONLDPresentationFormat}, &testDID, false)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
	})
	t.Run("JWT", func(t *testing.T) {
		options := PresentationOptions{Format: JWTPresentationFormat}
		t.Run("ok - one VC", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, false)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.ID, "id must be set")
			assert.Equal(t, testDID, did.MustParseDIDURL(result.ID.String()).DID, "id must be the DID of the holder")
			assert.NotEmpty(t, result.ID.Fragment, "id must have a fragment")
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
			nonce, _ := result.JWT().Get("nonce")
			assert.Empty(t, nonce)
		})
		t.Run("ok - multiple VCs", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDA.URI(), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential, testCredential}, options, &testDID, false)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
		})
		t.Run("optional proof options", func(t *testing.T) {
			exp := time.Now().Local().Truncate(time.Second)
			domain := "https://example.com"
			nonce := "the-nonce"
			options := PresentationOptions{
				Format: JWTPresentationFormat,
				ProofOptions: proof.ProofOptions{
					Expires: &exp,
					Created: exp.Add(-1 * time.Hour),
					Domain:  &domain,
					Nonce:   &nonce,
				},
			}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, false)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
			assert.Equal(t, *options.ProofOptions.Expires, result.JWT().Expiration().Local())
			assert.Equal(t, options.ProofOptions.Created, result.JWT().NotBefore().Local())
			assert.Equal(t, []string{domain}, result.JWT().Audience())
			actualNonce, _ := result.JWT().Get("nonce")
			assert.Equal(t, nonce, actualNonce)
		})
	})
	t.Run("validation", func(t *testing.T) {
		created := time.Now()
		options := PresentationOptions{ProofOptions: proof.ProofOptions{Created: created}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, mockVerifier, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, true)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created).Return(errors.New("failed"))

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, mockVerifier, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, true)

			assert.EqualError(t, err, "invalid credential (id="+testCredential.ID.String()+"): failed")
			assert.Nil(t, resultingPresentation)
		})
		t.Run("unsupported format", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(gomock.Any(), gomock.Any())

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, mockVerifier, jsonldManager, nil)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, PresentationOptions{Format: "paper"}, &testDID, true)

			assert.EqualError(t, err, "unsupported presentation proof format: paper")
			assert.Nil(t, result)
		})
	})
	t.Run("deriving signer from VCs", func(t *testing.T) {
		options := PresentationOptions{ProofOptions: proof.ProofOptions{}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential, testCredential}, options, nil, false)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error - not all VCs have the same id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{map[string]interface{}{"id": vdr.TestDIDB.String()}}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs have the same credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
		t.Run("error -  not all VCs have an id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			w := New(keyResolver, keyStore, nil, jsonldManager, nil)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: unable to get subject DID from VC: there must be at least 1 credentialSubject")
			assert.Nil(t, resultingPresentation)
		})
	})
}

func Test_wallet_Put(t *testing.T) {
	t.Run("put 1 credential", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		expected := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), expected)
		require.NoError(t, err)

		list, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected.ID.String(), list[0].ID.String())
	})
	t.Run("put 2 credentials", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		expected := []vc.VerifiableCredential{
			createCredential(vdr.TestMethodDIDA.String()),
			createCredential(vdr.TestMethodDIDB.String()),
		}

		err := sut.Put(context.Background(), expected...)
		require.NoError(t, err)

		// For DID A
		list, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected[0].ID.String(), list[0].ID.String())

		// For DID B
		list, err = sut.List(context.Background(), vdr.TestDIDB)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected[1].ID.String(), list[0].ID.String())
	})
	t.Run("put 3 credentials, 1 fails", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		expected := []vc.VerifiableCredential{
			createCredential(vdr.TestMethodDIDA.String()),
			createCredential(vdr.TestMethodDIDB.String()),
			{}, // no subject, causes error
		}

		err := sut.Put(context.Background(), expected...)
		require.Error(t, err)

		// For DID A
		list, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Empty(t, list)

		// For DID B
		list, err = sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Empty(t, list)
	})
	t.Run("duplicate credential", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		expected := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), expected)
		require.NoError(t, err)
		err = sut.Put(context.Background(), expected)
		require.NoError(t, err)

		list, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected.ID.String(), list[0].ID.String())
		assert.Equal(t, 1, sut.Diagnostics()[0].Result(), "duplicate credential should not increment total number of credentials")
	})
}

func Test_wallet_List(t *testing.T) {
	t.Run("invalid credential returns error", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		err := store.WriteShelf(context.Background(), vdr.TestDIDA.String(), func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey("invalid"), []byte("invalid"))
		})
		require.NoError(t, err)

		_, err = sut.List(context.Background(), vdr.TestDIDA)
		require.EqualError(t, err, "unable to list credentials: unable to unmarshal credential invalid: invalid character 'i' looking for beginning of value")
	})
}

func Test_wallet_Diagnostics(t *testing.T) {
	t.Run("empty wallet", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 0, actual[0].Result())
	})
	t.Run("1 credential", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		cred := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), cred)
		require.NoError(t, err)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 1, actual[0].Result())
	})
	t.Run("2 credentials", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)

		err := sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)
		err = sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 2, actual[0].Result())
	})
	t.Run("IO error", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)
		cred := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), cred)
		require.NoError(t, err)
		// Close store to cause error
		_ = store.Close(context.Background())

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 0, actual[0].Result())
	})
}

func createCredential(keyID string) vc.VerifiableCredential {
	testCredentialJSON := `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "company": {
            "city": "Hengelo",
            "name": "De beste zorg"
        },
        "id": "` + did.MustParseDIDURL(keyID).DID.String() + `"
    },
    "issuanceDate": "2021-12-24T13:21:29.087205+01:00",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "proof": {
        "created": "2021-12-24T13:21:29.087205+01:00",
        "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..hPM2GLc1K9d2D8Sbve004x9SumjLqaXTjWhUhvqWRwxfRWlwfp5gHDUYuRoEjhCXfLt-_u-knChVmK980N3LBw",
        "proofPurpose": "NutsSigningKeyType",
        "type": "JsonWebSignature2020",
        "verificationMethod": "` + keyID + `"
    },
    "type": [
        "CompanyCredential",
        "VerifiableCredential"
    ]
}`
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(testCredentialJSON), &testCredential)
	testCredential.ID, _ = ssi.ParseURI(testCredential.Issuer.String() + "#" + uuid.NewString())
	return testCredential
}

func Test_wallet_IsEmpty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)

		empty, err := sut.IsEmpty()

		require.NoError(t, err)
		assert.True(t, empty)
	})
	t.Run("2 credentials", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store)

		err := sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)

		empty, err := sut.IsEmpty()

		require.NoError(t, err)
		assert.False(t, empty)
	})
	t.Run("error", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		store, _ := storageEngine.GetProvider("test").GetKVStore("credentials", storage.PersistentStorageClass)
		sut := New(nil, nil, nil, nil, store).(*wallet)
		_ = sut.walletStore.Close(context.Background())

		_, err := sut.IsEmpty()

		require.Error(t, err)
	})
}
