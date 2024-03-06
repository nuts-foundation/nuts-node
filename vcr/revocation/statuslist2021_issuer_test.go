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

package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto"
	"strconv"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var aliceDID = did.MustParseDID("did:web:example.com:iam:alice")
var bobDID = did.MustParseDID("did:web:example.com:iam:bob")

func Test_TableNames(t *testing.T) {
	assert.Equal(t, credentialRecord{}.TableName(), "status_list_credential")
	assert.Equal(t, credentialIssuerRecord{}.TableName(), "status_list")
	assert.Equal(t, revocationRecord{}.TableName(), "status_list_entry")
}

func TestSqlStore_Create(t *testing.T) {
	s := newTestStatusList2021(t, aliceDID, bobDID) // NOTE: most tests re-use the same store, so they will fail when tests run out of order.
	testCtx := context.Background()

	var err error
	var entry *StatusList2021Entry

	t.Run("ok", func(t *testing.T) {

		t.Run("new issuer", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)
			// confirm empty DB
			assert.ErrorIs(t, s.db.First(new(credentialIssuerRecord), "subject_id = ?", statusListCredential).Error, gorm.ErrRecordNotFound)
			assert.ErrorIs(t, s.db.First(new(credentialRecord), "subject_id = ?", statusListCredential).Error, gorm.ErrRecordNotFound)

			entry, err = s.Entry(testCtx, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "0", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#0", statusListCredential), entry.ID)
			assert.Equal(t, StatusList2021EntryType, entry.Type)
			assert.Equal(t, StatusPurposeRevocation, entry.StatusPurpose)

			// confirm records created
			assert.NoError(t, s.db.First(new(credentialIssuerRecord), "subject_id = ?", statusListCredential).Error)
			assert.NoError(t, s.db.First(new(credentialRecord), "subject_id = ?", statusListCredential).Error)
		})
		t.Run("second entry", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)

			entry, err = s.Entry(testCtx, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "1", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#1", statusListCredential), entry.ID)

		})
		t.Run("credential rollover", func(t *testing.T) {
			statusListCredential, _ := toStatusListCredential(aliceDID, 1)
			// set last_issued_index to max value for a single credential so the next entry will be in page 2
			s.db.Model(&credentialIssuerRecord{}).
				Where("subject_id = ?", statusListCredential).
				Update("last_issued_index", maxBitstringIndex)
			statusListCredential, _ = toStatusListCredential(aliceDID, 2) // now expect page 2 to be used

			entry, err = s.Entry(testCtx, aliceDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)

			assert.Equal(t, statusListCredential, entry.StatusListCredential)
			assert.Equal(t, "0", entry.StatusListIndex)
			assert.Equal(t, fmt.Sprintf("%s#0", statusListCredential), entry.ID)
		})
		t.Run("second issuer", func(t *testing.T) {
			entry, err = s.Entry(testCtx, bobDID, StatusPurposeRevocation)

			assert.NoError(t, err)
			require.NotNil(t, entry)
			assert.Equal(t, "0", entry.StatusListIndex)
			// alice#1, alice#2, bob#1; fails if only part of the 'ok' block is executed
			assert.Equal(t, int64(3), s.db.Find(&[]credentialIssuerRecord{}).RowsAffected)
		})
	})
	t.Run("error - singing key not found", func(t *testing.T) {
		s := newTestStatusList2021(t, aliceDID, bobDID)
		s.ResolveKey = func(_ context.Context, _ did.DID) (crypto.Key, error) { return nil, errors.New("do re mi") }

		entry, err = s.Entry(testCtx, aliceDID, StatusPurposeRevocation)

		assert.EqualError(t, err, "do re mi")
		assert.Nil(t, entry)
	})
	t.Run("error - unsupported purpose", func(t *testing.T) {
		entry, err = s.Entry(testCtx, aliceDID, statusPurposeSuspension)
		assert.ErrorIs(t, err, errUnsupportedPurpose)
		assert.Nil(t, entry)
	})
	t.Run("error - unsupported DID method", func(t *testing.T) {
		entry, err = s.Entry(testCtx, did.MustParseDID("did:nuts:123"), StatusPurposeRevocation)
		assert.EqualError(t, err, "status list: unsupported DID method: nuts")
		assert.Nil(t, entry)
	})
	t.Run("no race conditions on UPDATE or CREATE", func(t *testing.T) {
		// raceFn creates 2 workers that race to complete the same job on the underlying SQL DB used in the store (must be empty).
		// In the first round they race to create a page for an issuer.
		// In the second round they race to update the last_issued_index for the page created in round 1.
		// The result is that each issuer has 1 (page) status list credential for which 4 entries are issued.
		raceFn := func(cs *StatusList2021) {
			const numJobs = 10

			// worker waits for a did, requests a statusListEntry for the did, and reports that it has completed.
			worker := func(dids <-chan did.DID, done chan<- struct{}) {
				defer close(done) // senders close
				for issuer := range dids {
					_, _ = cs.Entry(testCtx, issuer, StatusPurposeRevocation)
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
				storage.AddDIDtoSQLDB(t, cs.db, id)

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
			cs.db.Model(&credentialIssuerRecord{}).Count(&count)
			assert.Equal(t, int64(numJobs), count)

			// all have a unique issuer and have issued exactly 4 status list entries
			cs.db.Model(&credentialIssuerRecord{}).Distinct("issuer").Where("last_issued_index = 3").Count(&count)
			assert.Equal(t, int64(numJobs), count)
		}
		t.Run("sqlite", func(t *testing.T) {
			raceFn(newTestStatusList2021(t))
		})
		t.Run("postgres", func(t *testing.T) {
			t.SkipNow() // requires generation of postgres DB
			// create store with postgres DB
			var storePG *StatusList2021
			raceFn(storePG)
			// To confirm there was a race condition on the page creation (can't happen with SQLite), check the logs for:
			//		2024/02/12 19:53:20 .../nuts-node/vcr/revocation/... duplicated key not allowed
			// If this error was logged and the test did not fail it is handled correctly.
		})
	})
}

func TestSqlStore_Revoke(t *testing.T) {
	s := newTestStatusList2021(t, aliceDID, bobDID)

	entryP, err := s.Entry(nil, aliceDID, StatusPurposeRevocation)
	require.NoError(t, err)
	entry := *entryP

	t.Run("ok", func(t *testing.T) {
		statusListIndex := 0
		// confirm statuslist entry not revoked in credential
		credRecord, err := s.loadCredential(entry.StatusListCredential)
		require.NoError(t, err)
		set, _ := credRecord.Expanded.bit(statusListIndex)
		assert.False(t, set)
		credentialID := bobDID.URI() // not alice
		require.NoError(t, s.Revoke(nil, credentialID, entry))
		// confirm the revocation is in the DB
		var revocation revocationRecord
		err = s.db.Where(&revocationRecord{
			StatusListCredential: entry.StatusListCredential,
			StatusListIndex:      statusListIndex,
			CredentialID:         credentialID.String(),
		}).First(&revocation).Error
		assert.NoError(t, err)
		assert.InDelta(t, time.Now().Unix(), revocation.RevokedAt, 2) // allow 2 seconds difference for slow CI
		// confirm statuslist credential is updated
		credRecord, err = s.loadCredential(entry.StatusListCredential)
		require.NoError(t, err)
		set, _ = credRecord.Expanded.bit(statusListIndex)
		assert.True(t, set)
	})
	t.Run("error - signing key not found", func(t *testing.T) {
		s := newTestStatusList2021(t, aliceDID, bobDID)
		entry, err := s.Entry(nil, aliceDID, StatusPurposeRevocation)
		require.NoError(t, err)
		s.ResolveKey = func(_ context.Context, _ did.DID) (crypto.Key, error) { return nil, errors.New("no key") }
		assert.EqualError(t, s.Revoke(nil, ssi.URI{}, *entry), "no key")
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

func TestCredentialStatus_Credential(t *testing.T) {
	s := newTestStatusList2021(t, aliceDID, bobDID)
	auditCtx := audit.TestContext()

	// create status list credential for alice
	entryP, err := s.Entry(auditCtx, aliceDID, StatusPurposeRevocation)
	require.NoError(t, err)
	entry := *entryP

	t.Run("ok - empty bitstring", func(t *testing.T) {
		encodedList, err := compress(*newBitstring())
		assert.NoError(t, err)
		expectedCS := toMap(t, StatusList2021CredentialSubject{
			ID:            entry.StatusListCredential,
			Type:          StatusList2021CredentialSubjectType,
			StatusPurpose: StatusPurposeRevocation,
			EncodedList:   encodedList,
		})
		s.Sign = nil // guarantees credential comes from db
		defer func() { s.Sign = noopSign }()

		cred, err := s.Credential(auditCtx, aliceDID, 1)

		assert.NoError(t, err)
		require.NotNil(t, cred)
		assert.Equal(t, expectedCS, cred.CredentialSubject[0])
	})
	t.Run("ok - with revocations", func(t *testing.T) {
		require.NoError(t, s.Revoke(nil, ssi.URI{}, entry))
		s.Sign = nil // guarantees credential comes from db
		defer func() { s.Sign = noopSign }()

		cred, err := s.Credential(auditCtx, aliceDID, 1)
		assert.NoError(t, err)
		require.NotNil(t, cred)

		var credSubs []StatusList2021CredentialSubject
		require.NoError(t, cred.UnmarshalCredentialSubject(&credSubs))

		bs, err := expand(credSubs[0].EncodedList)
		assert.NoError(t, err)
		assert.NotEmpty(t, bs)
	})
	t.Run("ok - loadCredential failed", func(t *testing.T) {
		// add bob as issuer for page 0
		subjectID, err := toStatusListCredential(bobDID, 0)
		require.NoError(t, err)
		s.db.Create(&credentialIssuerRecord{
			SubjectID: subjectID,
			Issuer:    bobDID.String(),
		})
		// try load the credential
		cred, err := s.Credential(auditCtx, bobDID, 0)
		assert.NoError(t, err)
		assert.NotEmpty(t, cred)
	})
	t.Run("ok - refresh expired credential", func(t *testing.T) {
		// change expires so that time.Now is between refresh and expired
		err = s.db.Model(new(credentialRecord)).Where("subject_id = ?", entry.StatusListCredential).
			UpdateColumn("expires", time.Now().Add(minTimeUntilExpired-time.Second).Unix()).Error
		require.NoError(t, err)
		// try load the credential
		cred, err := s.Credential(auditCtx, aliceDID, 1)
		assert.NoError(t, err)
		assert.NotEmpty(t, cred)
	})
	t.Run("error - signing key not found", func(t *testing.T) {
		s := newTestStatusList2021(t, aliceDID)
		entry2, err := s.Entry(nil, aliceDID, StatusPurposeRevocation)
		require.NoError(t, err)
		// change expires to now so the StatusList2021Credential has to be signed again
		err = s.db.Model(new(credentialRecord)).Where("subject_id = ?", entry2.StatusListCredential).UpdateColumn("expires", time.Now()).Error
		require.NoError(t, err)
		s.ResolveKey = func(_ context.Context, _ did.DID) (crypto.Key, error) { return nil, errors.New("no key") }

		cred, err := s.Credential(auditCtx, aliceDID, 1)

		assert.EqualError(t, err, "no key")
		assert.Nil(t, cred)
	})
	t.Run("error - ErrNotFound", func(t *testing.T) {
		cred, err := s.Credential(auditCtx, aliceDID, 2)
		assert.ErrorIs(t, err, types.ErrNotFound)
		require.Nil(t, cred)
	})
}

func TestCredentialStatus_buildAndSignVC(t *testing.T) {
	cs := &StatusList2021{Sign: noopSign}

	subjectID, err := toStatusListCredential(aliceDID, 1)
	require.NoError(t, err)
	encodedList, err := compress(*newBitstring())
	require.NoError(t, err)
	expectedCS := StatusList2021CredentialSubject{
		ID:            subjectID,
		Type:          StatusList2021CredentialSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodedList,
	}

	cred, err := cs.buildAndSignVC(nil, aliceDID, expectedCS, nil)

	// signature is checked in vcr.issuer

	require.NoError(t, err)
	assert.True(t, cred.ContainsContext(vc.VCContextV1URI()))
	assert.True(t, cred.ContainsContext(StatusList2021ContextURI))
	assert.True(t, cred.IsType(vc.VerifiableCredentialTypeV1URI()))
	assert.True(t, cred.IsType(statusList2021CredentialTypeURI))
	assert.Contains(t, cred.ID.String(), aliceDID.String())
	assert.Equal(t, toMap(t, expectedCS), cred.CredentialSubject[0])
	assert.Equal(t, aliceDID.String(), cred.Issuer.String())
	assert.InDelta(t, time.Now().Unix(), cred.ValidFrom.Unix(), 2)
	assert.InDelta(t, time.Now().Add(statusListValidity).Unix(), cred.ValidUntil.Unix(), 2)
	assert.Nil(t, cred.IssuanceDate)
	assert.Nil(t, cred.ExpirationDate)
}

func toMap(t testing.TB, obj any) (result map[string]any) {
	bs, err := json.Marshal(obj)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(bs, &result))
	return
}
