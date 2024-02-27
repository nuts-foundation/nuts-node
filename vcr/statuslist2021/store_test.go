/*
 * Copyright (C) 2024 Nuts community
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

package statuslist2021

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var aliceDID = did.MustParseDID("did:web:example.com:iam:alice")
var bobDID = did.MustParseDID("did:web:example.com:iam:bob")

func Test_TableNames(t *testing.T) {
	assert.Equal(t, statusListCredentialRecord{}.TableName(), "status_list_credential")
	assert.Equal(t, revocationRecord{}.TableName(), "status_list_status")
}

func TestSqlStore_DB(t *testing.T) {
	s, err := NewStatusListStore(storage.NewTestStorageEngine(t).GetSQLDatabase())
	require.NoError(t, err)
	storage.AddDIDtoSQLDB(t, s.db, aliceDID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = s.DB(ctx).First(statusListCredentialRecord{}).Error
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSqlStore_Create(t *testing.T) {
	s, err := NewStatusListStore(storage.NewTestStorageEngine(t).GetSQLDatabase())
	require.NoError(t, err)
	storage.AddDIDtoSQLDB(t, s.db, aliceDID, bobDID) // NOTE: most tests re-use same store

	var entry *Entry

	t.Run("ok", func(t *testing.T) {

		t.Run("new issuer", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)

			entry, err = s.Create(nil, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "0", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#0", statusListCredential), entry.ID)
			assert.Equal(t, EntryType, entry.Type)
			assert.Equal(t, StatusPurposeRevocation, entry.StatusPurpose)
		})
		t.Run("second entry", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)

			entry, err = s.Create(nil, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "1", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#1", statusListCredential), entry.ID)

		})
		t.Run("credential rollover", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)
			// set last_issued_index to max value for a single credential so the next entry will be in page 2
			s.db.Model(&statusListCredentialRecord{}).
				Where("subject_id = ?", statusListCredential).
				Update("last_issued_index", maxBitstringIndex)
			statusListCredential, _ = toStatusListCredential(aliceDID, 2) // now expect page 2 to be used

			entry, err = s.Create(nil, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "0", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#0", statusListCredential), entry.ID)
		})
		t.Run("second issuer", func(t *testing.T) {
			entry, err = s.Create(nil, bobDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)
			assert.Equal(t, "0", entry.StatusListIndex)
			// alice#1, alice#2, bob#1; fails if only part of the 'ok' block is executed
			assert.Equal(t, int64(3), s.db.Find(&[]statusListCredentialRecord{}).RowsAffected)
		})
	})
	t.Run("error - unsupported purpose", func(t *testing.T) {
		entry, err = s.Create(nil, aliceDID, statusPurposeSuspension)
		assert.ErrorIs(t, err, errUnsupportedPurpose)
		assert.Nil(t, entry)
	})
	t.Run("error - unsupported DID method", func(t *testing.T) {
		entry, err = s.Create(nil, did.MustParseDID("did:nuts:123"), StatusPurposeRevocation)
		assert.EqualError(t, err, "status list: unsupported DID method: nuts")
		assert.Nil(t, entry)
	})
	t.Run("no race conditions on UPDATE or CREATE", func(t *testing.T) {
		// raceFn creates 2 workers that race to complete the same job on the underlying SQL DB used in the store (must be empty).
		// In the first round they race to create a page for an issuer.
		// In the second round they race to update the last_issued_index for the page created in round 1.
		// The result is that each issuer has 1 (page) status list credential for which 4 entries are issued.
		raceFn := func(store *sqlStore) {
			const numJobs = 10

			// worker waits for a did, requests a statusListEntry for the did, and reports that it has completed.
			worker := func(dids <-chan did.DID, done chan<- struct{}) {
				defer close(done) // senders close
				for issuer := range dids {
					_, _ = store.Create(nil, issuer, StatusPurposeRevocation)
					done <- struct{}{}
				}
			}

			// setup workers
			waitA, waitB := make(chan struct{}, 1), make(chan struct{}, 1)
			jobA, jobB := make(chan did.DID, 1), make(chan did.DID, 1)
			defer close(jobA)
			defer close(jobB)

			go worker(jobA, waitA)
			go worker(jobB, waitB)

			// run jobs by feeding the same did to both workers and wait until they both complete
			for j := 0; j < numJobs; j++ {
				// generate a new DID and add it to the VDR
				id := did.MustParseDID("did:web:example.com:iam:" + strconv.Itoa(j))
				storage.AddDIDtoSQLDB(t, store.db, id)

				// round 1; race on page (status_list_credential.id) creation
				jobA <- id
				jobB <- id
				<-waitB
				<-waitA

				// round 2; same job, but now race on updating last_issued_index
				jobA <- id
				jobB <- id
				<-waitB
				<-waitA
			}

			// number of status list credentials = numJobs
			var count int64
			store.db.Model(&statusListCredentialRecord{}).Count(&count)
			assert.Equal(t, int64(numJobs), count)

			// all have a unique issuer and have issued exactly 4 status list entries
			store.db.Model(&statusListCredentialRecord{}).Distinct("issuer").Where("last_issued_index = 3").Count(&count)
			assert.Equal(t, int64(numJobs), count)
		}
		t.Run("sqlite", func(t *testing.T) {
			store, err := NewStatusListStore(storage.NewTestStorageEngine(t).GetSQLDatabase())
			require.NoError(t, err)
			raceFn(store)
		})
		t.Run("postgres", func(t *testing.T) {
			t.SkipNow() // requires generation of postgres DB
			// create store with postgres DB
			var storePG *sqlStore
			raceFn(storePG)
			// To confirm there was a race condition on the page creation (can't happen with SQLite), check the logs for:
			//		2024/02/12 19:53:20 .../nuts-node/vcr/statuslist2021/store.go:196 duplicated key not allowed
			// If this error was logged and the test did not fail it is handled correctly.
		})
	})
}

func TestSqlStore_Revoke(t *testing.T) {
	s, err := NewStatusListStore(storage.NewTestStorageEngine(t).GetSQLDatabase())
	require.NoError(t, err)
	storage.AddDIDtoSQLDB(t, s.db, aliceDID, bobDID)

	entryP, err := s.Create(nil, aliceDID, StatusPurposeRevocation)
	require.NoError(t, err)
	entry := *entryP

	t.Run("ok", func(t *testing.T) {
		credentialID := bobDID.URI() // not alice
		assert.NoError(t, s.Revoke(nil, credentialID, entry))
		// confirm it is in the DB
		var revocation revocationRecord
		err = s.db.Where(&revocationRecord{
			StatusListCredential: entry.StatusListCredential,
			StatusListIndex:      0,
			CredentialID:         credentialID.String(),
		}).First(&revocation).Error
		assert.NoError(t, err)
		assert.InDelta(t, time.Now().Unix(), revocation.RevokedAt, 2) // allow 2 seconds difference for slow CI
	})
	t.Run("error - ErrRevoked", func(t *testing.T) {
		assert.ErrorIs(t, s.Revoke(nil, ssi.URI{}, entry), types.ErrRevoked)
	})
	t.Run("error - unsupportedPurpose", func(t *testing.T) {
		cEntry := entry
		cEntry.StatusPurpose = statusPurposeSuspension
		assert.ErrorIs(t, s.Revoke(nil, ssi.URI{}, cEntry), errUnsupportedPurpose)
	})
	t.Run("error - ErrNotFound", func(t *testing.T) {
		cEntry := entry
		cEntry.StatusListCredential += "unknown"
		assert.ErrorIs(t, s.Revoke(nil, ssi.URI{}, cEntry), types.ErrNotFound)
	})
	t.Run("error - statusListIndex NaN", func(t *testing.T) {
		cEntry := entry
		cEntry.StatusListIndex = "NaN"
		assert.ErrorContains(t, s.Revoke(nil, ssi.URI{}, cEntry), "invalid syntax")
	})
	t.Run("error - statusListIndex OOB", func(t *testing.T) {
		cEntry := entry
		cEntry.StatusListIndex = "10"
		assert.ErrorIs(t, s.Revoke(nil, ssi.URI{}, cEntry), ErrIndexNotInBitstring)
	})
}

func TestSqlStore_CredentialSubject(t *testing.T) {
	s, err := NewStatusListStore(storage.NewTestStorageEngine(t).GetSQLDatabase())
	require.NoError(t, err)
	storage.AddDIDtoSQLDB(t, s.db, aliceDID, bobDID)

	// create status list credential for alice
	entryP, err := s.Create(nil, aliceDID, StatusPurposeRevocation)
	require.NoError(t, err)
	entry := *entryP

	t.Run("ok - empty bitstring", func(t *testing.T) {
		encodedList, err := compress(*newBitstring())
		assert.NoError(t, err)
		expectedCS := CredentialSubject{
			Id:            entry.StatusListCredential,
			Type:          CredentialSubjectType,
			StatusPurpose: StatusPurposeRevocation,
			EncodedList:   encodedList,
		}

		cs, err := s.CredentialSubject(nil, aliceDID, 1)

		assert.NoError(t, err)
		require.NotNil(t, cs)
		assert.Equal(t, expectedCS, *cs)
	})
	t.Run("ok - with revocations", func(t *testing.T) {
		require.NoError(t, s.Revoke(nil, ssi.URI{}, entry))

		cs, err := s.CredentialSubject(nil, aliceDID, 1)
		assert.NoError(t, err)
		require.NotNil(t, cs)

		bs, err := expand(cs.EncodedList)
		assert.NoError(t, err)
		assert.NotEmpty(t, bs)
	})
	t.Run("error - ErrNotFound", func(t *testing.T) {
		cs, err := s.CredentialSubject(nil, aliceDID, 2)
		assert.ErrorIs(t, err, types.ErrNotFound)
		require.Nil(t, cs)
	})
	t.Run("error - unsupported DID method", func(t *testing.T) {
		cs, err := s.CredentialSubject(nil, did.MustParseDID("did:nuts:123"), 1)
		assert.EqualError(t, err, "status list: unsupported DID method: nuts")
		require.Nil(t, cs)
	})
}
