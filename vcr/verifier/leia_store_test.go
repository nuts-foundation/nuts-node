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
	"crypto/sha1"
	"encoding/json"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"path"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

func TestNewLeiaVerifierStore(t *testing.T) {
	backupStore := newMockKVStore(t)

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
		sut, err := NewLeiaVerifierStore(verifierStorePath, backupStore)

		assert.NoError(t, err)
		assert.IsType(t, &leiaVerifierStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		sut, err := NewLeiaVerifierStore("/", nil)

		assert.Contains(t, err.Error(), "failed to create leiaVerifierStore:")
		assert.Nil(t, sut)
	})
}

func TestLeiaStore_Close(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	backupStore := newMockKVStore(t)
	sut, _ := NewLeiaVerifierStore(verifierStorePath, backupStore)
	err := sut.Close()
	assert.NoError(t, err)
}

func Test_leiaVerifierStore_StoreRevocation(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	backupStore := newMockKVStore(t)
	sut, _ := NewLeiaVerifierStore(verifierStorePath, backupStore)

	t.Run("it stores a revocation and can find it back", func(t *testing.T) {
		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}
		err := sut.StoreRevocation(*revocation)
		assert.NoError(t, err)
		result, err := sut.GetRevocations(subjectID)
		assert.NoError(t, err)
		assert.Equal(t, []*credential.Revocation{revocation}, result)
	})
}

func Test_leiaVerifierStore_GetRevocation(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	backupStore := newMockKVStore(t)
	sut, _ := NewLeiaVerifierStore(verifierStorePath, backupStore)
	subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
	revocation := &credential.Revocation{Subject: subjectID}
	assert.NoError(t, sut.StoreRevocation(*revocation))

	t.Run("it can find a revocation", func(t *testing.T) {
		result, err := sut.GetRevocations(subjectID)
		assert.NoError(t, err)
		assert.Equal(t, []*credential.Revocation{revocation}, result)
	})

	t.Run("it returns a ErrNotFound when revocation could not be found", func(t *testing.T) {
		unknownSubjectID := ssi.MustParseURI("did:nuts:456#ab-cde")
		result, err := sut.GetRevocations(unknownSubjectID)
		assert.EqualError(t, err, "not found")
		assert.Nil(t, result)
	})
}

func Test_leiaVerifierStore_Diagnostics(t *testing.T) {
	backupStore := newMockKVStore(t)
	t.Run("empty", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
		sut, _ := NewLeiaVerifierStore(verifierStorePath, backupStore)

		actual := sut.Diagnostics()
		assert.Len(t, actual, 1)
		assert.Equal(t, "revocations_count", actual[0].Name())
		assert.Equal(t, 0, actual[0].Result())
	})
	t.Run("not empty", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
		sut, _ := NewLeiaVerifierStore(verifierStorePath, backupStore)

		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}
		_ = sut.StoreRevocation(*revocation)

		actual := sut.Diagnostics()
		assert.Len(t, actual, 1)
		assert.Equal(t, 1, actual[0].Result())
	})
}

func Test_restoreFromShelf(t *testing.T) {
	testDir := io.TestDirectory(t)
	issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
	backupStorePath := path.Join(testDir, "vcr", "backup-revoked-credentials.db")
	backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
	revocation := &credential.Revocation{Subject: subjectID}
	bytes, _ := json.Marshal(revocation)
	ref := sha1.Sum(bytes)
	_ = backupStore.WriteShelf(context.Background(), revocationBackupShelf, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(ref[:]), bytes)
	})

	store, err := NewLeiaVerifierStore(issuerStorePath, backupStore)
	require.NoError(t, err)
	result, err := store.GetRevocations(subjectID)
	require.NoError(t, err)
	assert.Equal(t, []*credential.Revocation{revocation}, result)
}

// newMockKVStore create a mockStore with contents
func newMockKVStore(t *testing.T) stoabs.KVStore {
	ctrl := gomock.NewController(t)
	backupStore := stoabs.NewMockKVStore(ctrl)
	mockReader := stoabs.NewMockReader(ctrl)
	mockReader.EXPECT().Empty().Return(false, nil).AnyTimes()
	mockReader.EXPECT().Iterate(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	backupStore.EXPECT().ReadShelf(context.Background(), revocationBackupShelf, gomock.Any()).Do(func(arg0 context.Context, arg1 string, arg2 func(reader stoabs.Reader) error) error {
		return arg2(mockReader)
	}).AnyTimes()
	return backupStore
}
