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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
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
				res, err := sut.SearchCredential(vcToStore.Type[0], *issuerDID, nil)
				assert.NoError(t, err)
				require.Len(t, res, 1)

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("for all issued credentials for a issuer and subject", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Type[0], *issuerDID, &subjectID)
				assert.NoError(t, err)
				require.Len(t, res, 1)

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("without context", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Type[0], *issuerDID, nil)
				assert.NoError(t, err)
				require.Len(t, res, 1)

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("no results", func(t *testing.T) {

				t.Run("unknown issuer", func(t *testing.T) {
					unknownIssuerDID, _ := did.ParseDID("did:nuts:123")
					res, err := sut.SearchCredential(vcToStore.Type[0], *unknownIssuerDID, nil)
					assert.NoError(t, err)
					require.Len(t, res, 0)
				})

				t.Run("unknown credentialType", func(t *testing.T) {
					unknownType := ssi.MustParseURI("unknownType")
					res, err := sut.SearchCredential(unknownType, *issuerDID, nil)
					assert.NoError(t, err)
					require.Len(t, res, 0)
				})

				t.Run("unknown subject", func(t *testing.T) {
					unknownSubject := ssi.MustParseURI("did:nuts:unknown")
					res, err := sut.SearchCredential(vcToStore.Type[0], *issuerDID, &unknownSubject)
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
		assert.ErrorIs(t, err, types.ErrNotFound)
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
			assert.ErrorIs(t, err, types.ErrMultipleFound)
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

		assert.ErrorIs(t, err, types.ErrNotFound)
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

		assert.ErrorIs(t, err, types.ErrMultipleFound)
		assert.Nil(t, result)
	})
}

func TestNewLeiaIssuerStore(t *testing.T) {
	t.Run("bug test for https://github.com/nuts-foundation/nuts-node/issues/1909", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		backupMockStore := stoabs.NewMockKVStore(ctrl)
		backupStorePath := path.Join(t.TempDir(), "backup-issued-credentials.db")
		emptyBackupStore, err := bbolt.CreateBBoltStore(backupStorePath)
		dbPath := path.Join(t.TempDir(), "issuer.db")

		// first create a store with 1 credential
		store, err := NewLeiaIssuerStore(dbPath, emptyBackupStore)
		require.NoError(t, err)
		vc := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestCredential), &vc)
		require.NoError(t, store.StoreCredential(vc))
		require.NoError(t, store.Close())

		// now create a new store with a mock backup and show that ReadShelf is only called once.
		// additional calls to the backup store would indicate the main store is empty and the backup is used to restore the main storage.
		reader := stoabs.NewMockReader(ctrl)
		reader.EXPECT().Empty().Return(false, nil)
		backupMockStore.EXPECT().ReadShelf(gomock.Any(), "credentials", gomock.Any()).DoAndReturn(func(context interface{}, shelfName interface{}, callback interface{}) error {
			f := callback.(func(reader stoabs.Reader) error)
			return f(reader)
		})
		backupMockStore.EXPECT().ReadShelf(gomock.Any(), "revocations", gomock.Any()).DoAndReturn(func(context interface{}, shelfName interface{}, fn interface{}) error {
			return nil
		})
		_, err = NewLeiaIssuerStore(dbPath, backupMockStore)
		require.NoError(t, err)
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
