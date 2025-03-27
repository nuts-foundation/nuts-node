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
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
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

func TestWallet_BuildPresentation(t *testing.T) {
	var kid = vdr.TestMethodDIDA.String()
	testCredential := createCredential(kid)
	key := vdr.TestMethodDIDAPrivateKey()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	testDID := vdr.TestDIDA
	ctx := audit.TestContext()

	keyStorage := crypto.NewMemoryStorage()
	_ = keyStorage.SavePrivateKey(ctx, key.KID, key.PrivateKey)
	storageEngine := storage.NewTestStorageEngine(t)
	keyStore := crypto.NewTestCryptoInstance(storageEngine.GetSQLDatabase(), keyStorage)
	_ = keyStore.Link(ctx, key.KID, key.KID, "1")

	t.Run("validation", func(t *testing.T) {
		created := time.Now()
		options := PresentationOptions{ProofOptions: proof.ProofOptions{Created: created}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().VerifySignature(testCredential, &created)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(kid, key.PublicKey, nil)

			w := NewSQLWallet(keyResolver, keyStore, mockVerifier, jsonldManager, storageEngine)

			resultingPresentation, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, true)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("unsupported format", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().VerifySignature(gomock.Any(), gomock.Any())

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(kid, key.PublicKey, nil)

			w := NewSQLWallet(keyResolver, keyStore, mockVerifier, jsonldManager, storageEngine)

			result, err := w.BuildPresentation(ctx, []vc.VerifiableCredential{testCredential}, PresentationOptions{Format: "paper"}, &testDID, true)

			assert.EqualError(t, err, "unsupported presentation proof format: paper")
			assert.Nil(t, result)
		})
	})
}

func Test_sqlWallet_Put(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	t.Run("put 1 credential", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
		expected := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), expected)
		require.NoError(t, err)

		list, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected.ID.String(), list[0].ID.String())
	})
	t.Run("put 2 credentials", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
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
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
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
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
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

func Test_sqlWallet_List(t *testing.T) {
	ctx := context.Background()
	storageEngine := storage.NewTestStorageEngine(t)
	t.Run("empty", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)

		list, err := sut.List(ctx, vdr.TestDIDA)
		require.NoError(t, err)
		require.NotNil(t, list)
		assert.Empty(t, list)
	})
	t.Run("not empty", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
		expected := createCredential(vdr.TestMethodDIDA.String())
		err := sut.Put(ctx, expected, createCredential(vdr.TestMethodDIDB.String()))
		require.NoError(t, err)

		list, err := sut.List(ctx, vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, expected.ID.String(), list[0].ID.String())
	})
	t.Run("expired credential", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{err: types.ErrCredentialNotValidAtTime}, nil, storageEngine)
		expected := createCredential(vdr.TestMethodDIDA.String())
		err := sut.Put(ctx, expected, createCredential(vdr.TestMethodDIDB.String()))
		require.NoError(t, err)

		list, err := sut.List(ctx, vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 0)
	})
	t.Run("other error", func(t *testing.T) {
		captureLogs := audit.CaptureLogs(t, logrus.StandardLogger())
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{err: assert.AnError}, nil, storageEngine)
		expected := createCredential(vdr.TestMethodDIDA.String())
		err := sut.Put(ctx, expected, createCredential(vdr.TestMethodDIDB.String()))
		require.NoError(t, err)

		list, err := sut.List(ctx, vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list, 0)
		require.NotNil(t, captureLogs.Hook.LastEntry())
		assert.Equal(t, "unable to verify credential", captureLogs.Hook.LastEntry().Message)
	})
}

func Test_sqlWallet_Diagnostics(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	t.Run("empty wallet", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 0, actual[0].Result())
	})
	t.Run("1 credential", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)
		cred := createCredential(vdr.TestMethodDIDA.String())

		err := sut.Put(context.Background(), cred)
		require.NoError(t, err)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 1, actual[0].Result())
	})
	t.Run("2 credentials", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)

		err := sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)
		err = sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)

		actual := sut.Diagnostics()
		require.Len(t, actual, 1)
		assert.Equal(t, "credential_count", actual[0].Name())
		assert.Equal(t, 2, actual[0].Result())
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
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#` + uuid.NewString() + `",
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
	return testCredential
}

func Test_sqlWallet_IsEmpty(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	t.Run("empty", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)

		empty, err := sut.IsEmpty()

		require.NoError(t, err)
		assert.True(t, empty)
	})
	t.Run("2 credentials", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storageEngine)

		err := sut.Put(context.Background(), createCredential(vdr.TestMethodDIDA.String()))
		require.NoError(t, err)

		empty, err := sut.IsEmpty()

		require.NoError(t, err)
		assert.False(t, empty)
	})
}

func Test_sqlWalletStore_remove(t *testing.T) {
	engine := storage.NewTestStorageEngine(t)
	require.NoError(t, engine.Start())
	t.Run("ok", func(t *testing.T) {
		resetStore(t, engine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storage.NewTestStorageEngine(t))

		auditLogs := audit.CaptureAuditLogs(t)

		// Have 3 credentials in wallet, 2 of the subject wallet, 1 of another wallet
		credentialToRemove := createCredential(vdr.TestMethodDIDA.String())
		err := sut.Put(context.Background(), credentialToRemove)
		require.NoError(t, err)
		otherCredential1 := createCredential(vdr.TestMethodDIDA.String())
		err = sut.Put(context.Background(), otherCredential1)
		require.NoError(t, err)
		otherCredential2 := createCredential(vdr.TestMethodDIDB.String())
		err = sut.Put(context.Background(), otherCredential2)
		require.NoError(t, err)

		err = sut.Remove(audit.TestContext(), vdr.TestDIDA, *credentialToRemove.ID)
		require.NoError(t, err)

		// Make sure the other 2 credentials weren't removed
		list1, err := sut.List(context.Background(), vdr.TestDIDA)
		require.NoError(t, err)
		require.Len(t, list1, 1)
		assert.Equal(t, otherCredential1.ID.String(), list1[0].ID.String())
		list2, err := sut.List(context.Background(), vdr.TestDIDB)
		require.NoError(t, err)
		require.Len(t, list2, 1)

		// Assert action is audited
		auditLogs.AssertContains(t, "VCR", "VerifiableCredentialRemovedEvent", audit.TestActor, "Removed credential from wallet")
	})
	t.Run("not found", func(t *testing.T) {
		resetStore(t, engine.GetSQLDatabase())
		sut := NewSQLWallet(nil, nil, testVerifier{}, nil, storage.NewTestStorageEngine(t))

		err := sut.Remove(context.Background(), vdr.TestDIDA, ssi.MustParseURI("did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#123"))
		assert.ErrorIs(t, err, types.ErrNotFound)
	})
}

func resetStore(t *testing.T, db *gorm.DB) {
	// for range delete form
	tableNames := []string{"wallet_credential", "credential", "credential_prop"}
	for _, tableName := range tableNames {
		require.NoError(t, db.Exec("DELETE FROM "+tableName).Error)
	}
}

type testVerifier struct {
	err error
}

func (t testVerifier) Verify(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	return t.err
}

func (t testVerifier) VerifySignature(credentialToVerify vc.VerifiableCredential, at *time.Time) error {
	panic("implement me")
}

func (t testVerifier) IsRevoked(credentialID ssi.URI) (bool, error) {
	panic("implement me")
}

func (t testVerifier) GetRevocation(id ssi.URI) (*credential.Revocation, error) {
	panic("implement me")
}

func (t testVerifier) RegisterRevocation(revocation credential.Revocation) error {
	panic("implement me")
}

func (t testVerifier) VerifyVP(presentation vc.VerifiablePresentation, verifyVCs bool, allowUntrustedVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error) {
	panic("implement me")
}
