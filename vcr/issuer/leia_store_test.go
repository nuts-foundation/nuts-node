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

package issuer

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/stretchr/testify/require"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

func TestNewLeiaStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		sut := newStore(t)

		assert.IsType(t, &leiaIssuerStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		sut, err := NewLeiaIssuerStore("/", nil)

		assert.Contains(t, err.Error(), "failed to create leiaIssuerStore:")
		assert.Nil(t, sut)
	})
}

func TestLeiaStore_Close(t *testing.T) {
	sut := newStore(t)

	err := sut.Close()

	assert.NoError(t, err)
}

func TestLeiaIssuerStore_StoreCredential(t *testing.T) {
	ctx := context.Background()
	vcToStore := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToStore)

	t.Run("fail on backup store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		ctrl := gomock.NewController(t)
		backupStore := stoabs.NewMockKVStore(ctrl)
		backupStore.EXPECT().ReadShelf(ctx, issuedBackupShelf, gomock.Any()).Return(nil)
		backupStore.EXPECT().ReadShelf(ctx, revocationBackupShelf, gomock.Any()).Return(nil)
		backupStore.EXPECT().WriteShelf(ctx, issuedBackupShelf, gomock.Any()).Return(errors.New("failure"))
		store, err := NewLeiaIssuerStore(issuerStorePath, backupStore)
		require.NoError(t, err)

		err = store.StoreCredential(vcToStore)

		assert.Error(t, err)
	})
}

func Test_leiaStore_StoreAndSearchCredential(t *testing.T) {
	vcToStore := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToStore)

	t.Run("store", func(t *testing.T) {
		sut := newStore(t)

		err := sut.StoreCredential(vcToStore)
		assert.NoError(t, err)

		t.Run("and search", func(t *testing.T) {
			issuerDID, _ := did.ParseDID(vcToStore.Issuer.String())
			subjectID := ssi.MustParseURI("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

			t.Run("for all issued credentials for a issuer", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[1], vcToStore.Type[0], *issuerDID, nil)
				assert.NoError(t, err)
				require.Len(t, res, 1)

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("for all issued credentials for a issuer and subject", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, &subjectID)
				assert.NoError(t, err)
				require.Len(t, res, 1)

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("no results", func(t *testing.T) {

				t.Run("unknown issuer", func(t *testing.T) {
					unknownIssuerDID, _ := did.ParseDID("did:nuts:123")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *unknownIssuerDID, nil)
					assert.NoError(t, err)
					require.Len(t, res, 0)
				})

				t.Run("unknown credentialType", func(t *testing.T) {
					unknownType := ssi.MustParseURI("unknownType")
					res, err := sut.SearchCredential(vcToStore.Context[0], unknownType, *issuerDID, nil)
					assert.NoError(t, err)
					require.Len(t, res, 0)
				})

				t.Run("unknown subject", func(t *testing.T) {
					unknownSubject := ssi.MustParseURI("did:nuts:unknown")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, &unknownSubject)
					assert.NoError(t, err)
					require.Len(t, res, 0)
				})
			})

		})
	})

}

func Test_leiaStore_GetCredential(t *testing.T) {
	vcToGet := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToGet)

	t.Run("with a known credential", func(t *testing.T) {
		store := newStore(t)
		assert.NoError(t, store.StoreCredential(vcToGet))
		t.Run("it finds the credential by id", func(t *testing.T) {
			foundCredential, err := store.GetCredential(*vcToGet.ID)
			assert.NoError(t, err)
			assert.Equal(t, *foundCredential, vcToGet)
		})
	})

	t.Run("no results", func(t *testing.T) {
		store := newStore(t)
		foundCredential, err := store.GetCredential(*vcToGet.ID)
		assert.EqualError(t, err, ErrNotFound.Error())
		assert.Nil(t, foundCredential)
	})

	t.Run("multiple results", func(t *testing.T) {
		store := newStore(t)
		// store once
		assert.NoError(t, store.StoreCredential(vcToGet))
		// store twice
		lstore := store.(*leiaIssuerStore)
		rawStructWithSameID := struct {
			ID *ssi.URI `json:"id,omitempty"`
		}{ID: vcToGet.ID}
		asBytes, _ := json.Marshal(rawStructWithSameID)
		lstore.issuedCredentials.Add([]leia.Document{asBytes})

		t.Run("it fails", func(t *testing.T) {
			foundCredential, err := store.GetCredential(*vcToGet.ID)
			assert.ErrorIs(t, err, ErrMultipleFound)
			assert.Nil(t, foundCredential)
		})
	})
}

func Test_leiaIssuerStore_StoreRevocation(t *testing.T) {
	store := newStore(t)

	t.Run("it stores a revocation and can find it back", func(t *testing.T) {
		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}

		err := store.StoreRevocation(*revocation)
		require.NoError(t, err)
		result, err := store.GetRevocation(subjectID)

		assert.NoError(t, err)
		assert.Equal(t, revocation, result)
	})
}

func Test_leiaIssuerStore_GetRevocation(t *testing.T) {
	store := newStore(t)
	subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
	revocation := &credential.Revocation{Subject: subjectID}
	assert.NoError(t, store.StoreRevocation(*revocation))

	t.Run("it can find a revocation", func(t *testing.T) {
		result, err := store.GetRevocation(subjectID)

		assert.NoError(t, err)
		assert.Equal(t, revocation, result)
	})

	t.Run("it returns a ErrNotFound when revocation could not be found", func(t *testing.T) {
		unknownSubjectID := ssi.MustParseURI("did:nuts:456#ab-cde")

		result, err := store.GetRevocation(unknownSubjectID)

		assert.ErrorIs(t, err, ErrNotFound)
		assert.Nil(t, result)
	})

	t.Run("it fails when multiple revocations exist", func(t *testing.T) {
		duplicateSubjectID := ssi.MustParseURI("did:nuts:456#ab-duplicate")
		revocation := &credential.Revocation{Subject: duplicateSubjectID}
		for i := 0; i < 2; i++ {
			revocation.Reason = fmt.Sprintf("revocation reason %d", i)
			require.NoError(t, store.StoreRevocation(*revocation))
		}

		result, err := store.GetRevocation(duplicateSubjectID)

		assert.ErrorIs(t, err, ErrMultipleFound)
		assert.Nil(t, result)
	})
}

func TestLeiaIssuerStore_handleRestore(t *testing.T) {
	ctx := context.Background()
	t.Run("credentials", func(t *testing.T) {
		document := []byte(jsonld.TestCredential)
		ref := defaultReference(document)
		vc := vc.VerifiableCredential{}
		_ = json.Unmarshal(document, &vc)

		t.Run("both empty", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)

			err := store.handleRestore(store.issuedCredentials, issuedBackupShelf, "id")

			assert.NoError(t, err)
			assert.False(t, storePresent(store.issuedCredentials, "id"))
			assert.False(t, store.backupStorePresent(issuedBackupShelf))
		})

		t.Run("both present", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)
			err := store.StoreCredential(vc)
			require.NoError(t, err)

			err = store.handleRestore(store.issuedCredentials, issuedBackupShelf, "id")

			assert.NoError(t, err)
			assert.True(t, storePresent(store.issuedCredentials, "id"))
			assert.True(t, store.backupStorePresent(issuedBackupShelf))
		})

		t.Run("only backup present", func(t *testing.T) {
			testDir := io.TestDirectory(t)
			backupStorePath := path.Join(testDir, "vcr", "backup-issued-credentials.db")
			backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
			require.NoError(t, err)
			err = backupStore.WriteShelf(ctx, issuedBackupShelf, func(writer stoabs.Writer) error {
				return writer.Put(stoabs.BytesKey(ref), document)
			})
			require.NoError(t, err)
			backupStore.Close(context.Background())
			store := newStoreInDir(t, testDir).(*leiaIssuerStore)

			err = store.handleRestore(store.issuedCredentials, issuedBackupShelf, "id")

			require.NoError(t, err)
			indexedVC, err := store.GetCredential(*vc.ID)
			require.NoError(t, err)
			assert.NotNil(t, indexedVC)
		})

		t.Run("only index present", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)
			err := store.issuedCredentials.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.handleRestore(store.issuedCredentials, issuedBackupShelf, "id")

			require.NoError(t, err)
			_ = store.backupStore.ReadShelf(ctx, issuedBackupShelf, func(reader stoabs.Reader) error {
				val, err := reader.Get(stoabs.BytesKey(ref))
				assert.NoError(t, err)
				assert.NotNil(t, val)
				return nil
			})
		})
	})

	t.Run("revocations", func(t *testing.T) {
		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}
		revocationBytes, _ := json.Marshal(revocation)
		ref := defaultReference(revocationBytes)

		t.Run("both empty", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)

			err := store.handleRestore(store.revokedCredentials, revocationBackupShelf, credential.RevocationSubjectPath)

			assert.NoError(t, err)
			assert.False(t, storePresent(store.revokedCredentials, credential.RevocationSubjectPath))
			assert.False(t, store.backupStorePresent(revocationBackupShelf))
		})

		t.Run("both present", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)
			err := store.StoreRevocation(*revocation)
			require.NoError(t, err)

			err = store.handleRestore(store.revokedCredentials, revocationBackupShelf, credential.RevocationSubjectPath)

			assert.NoError(t, err)
			assert.True(t, storePresent(store.revokedCredentials, credential.RevocationSubjectPath))
			assert.True(t, store.backupStorePresent(revocationBackupShelf))
		})

		t.Run("only backup present", func(t *testing.T) {
			testDir := io.TestDirectory(t)
			backupStorePath := path.Join(testDir, "vcr", "backup-issued-credentials.db")
			backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
			require.NoError(t, err)
			err = backupStore.WriteShelf(ctx, revocationBackupShelf, func(writer stoabs.Writer) error {
				return writer.Put(stoabs.BytesKey(ref), revocationBytes)
			})
			require.NoError(t, err)
			backupStore.Close(context.Background())
			store := newStoreInDir(t, testDir).(*leiaIssuerStore)

			err = store.handleRestore(store.revokedCredentials, revocationBackupShelf, credential.RevocationSubjectPath)

			require.NoError(t, err)
			indexedRevocation, err := store.GetRevocation(revocation.Subject)
			require.NoError(t, err)
			assert.NotNil(t, indexedRevocation)
		})

		t.Run("only index present", func(t *testing.T) {
			store := newStore(t).(*leiaIssuerStore)
			err := store.revokedCredentials.Add([]leia.Document{revocationBytes})
			require.NoError(t, err)

			err = store.handleRestore(store.revokedCredentials, revocationBackupShelf, credential.RevocationSubjectPath)

			require.NoError(t, err)
			_ = store.backupStore.ReadShelf(ctx, revocationBackupShelf, func(reader stoabs.Reader) error {
				val, err := reader.Get(stoabs.BytesKey(ref))
				assert.NoError(t, err)
				assert.NotNil(t, val)
				return nil
			})
		})
	})
}

func Test_leiaIssuerStore_Diagnostics(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		store := newStore(t)

		actual := store.Diagnostics()

		assert.Len(t, actual, 2)
		assert.Equal(t, 0, actual[0].Result())
		assert.Equal(t, 0, actual[1].Result())
	})
	t.Run("credential", func(t *testing.T) {
		store := newStore(t)
		vcToStore := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToStore)
		_ = store.StoreCredential(vcToStore)

		actual := store.Diagnostics()

		assert.Len(t, actual, 2)
		assert.Equal(t, "issued_credentials_count", actual[0].Name())
		assert.Equal(t, 1, actual[0].Result())
		assert.Equal(t, "revoked_credentials_count", actual[1].Name())
		assert.Equal(t, 0, actual[1].Result())
	})
	t.Run("revocation", func(t *testing.T) {
		store := newStore(t)
		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}
		_ = store.StoreRevocation(*revocation)

		actual := store.Diagnostics()

		assert.Len(t, actual, 2)
		assert.Equal(t, 0, actual[0].Result())
		assert.Equal(t, 1, actual[1].Result())
	})
}

func newStore(t *testing.T) Store {
	testDir := io.TestDirectory(t)
	return newStoreInDir(t, testDir)
}

func newStoreInDir(t *testing.T, testDir string) Store {
	issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
	backupStorePath := path.Join(testDir, "vcr", "backup-issued-credentials.db")
	backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	store, err := NewLeiaIssuerStore(issuerStorePath, backupStore)
	require.NoError(t, err)
	return store
}

func defaultReference(doc leia.Document) leia.Reference {
	s := sha1.Sum(doc)
	var b = make([]byte, len(s))
	copy(b, s[:])

	return b
}
