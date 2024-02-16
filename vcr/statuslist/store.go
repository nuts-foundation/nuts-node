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

package statuslist

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// errNotFound wraps types.ErrNotFound to clarify which credential is not found
var errNotFound = fmt.Errorf("status list: %w", types.ErrNotFound)

// errUnsupportedPurpose limits current usage to 'revocation'
var errUnsupportedPurpose = errors.New("status list: purpose not supported")

// errNotFound wraps types.ErrRevoked to clarify the source of the error
var errRevoked = fmt.Errorf("status list: %w", types.ErrRevoked)

type StatusPurpose string

const (
	StatusPurposeRevocation = "revocation"
	statusPurposeSuspension = "suspension" // currently not supported
)

// StatusList2021Issuer keeps track of the number of credentials with a credential status per issuer, and allows revoking
// them by setting the relevant bit on the StatusList.
// Individual statuses should be derived from the StatusList2021Credential(s), not inspected here.
type StatusList2021Issuer interface {
	// CredentialSubject creates a StatusList2021CredentialSubject to incorporate in a StatusList2021Credential issued by issuer.
	CredentialSubject(ctx context.Context, issuer did.DID, page int) (*StatusList2021CredentialSubject, error)
	// Create a credential.StatusList2021Entry that can be added to the credentialStatus of a VC.
	// The corresponding credential will have a gap in the bitstring if the returned entry does not make it into a credential.
	Create(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*StatusList2021Entry, error)
	// Revoke by adding StatusList2021Entry to the list of revocations.
	// The credentialID is only used to allow reverse search of revocations, its issuer is NOT compared to the entry issuer.
	// Returns types.ErrRevoked if already revoked, or types.ErrNotFound when the entry.StatusListCredential is unknown.
	Revoke(ctx context.Context, credentialID ssi.URI, entry StatusList2021Entry) error
}

func (s statusListCredentialRecord) TableName() string {
	return "status_list_credential"
}

// statusListCredentialRecord keeps track of the StatusListCredential issued by an issuer, and what the LastIssuedIndex is for each credential.
type statusListCredentialRecord struct {
	// SubjectID is the VC.CredentialSubject.ID for this StatusListCredential.
	// It is the URL where the credential can be downloaded e.g., https://example.com/iam/id/statuslist/1.
	SubjectID string `gorm:"primaryKey"`
	// Issuer of the StatusListCredential.
	Issuer string
	// Page number corresponding to this SubjectID.
	Page int
	// LastIssuedIndex on this page. Range:  0 <= StatusListIndex < statuslist2021.MaxBitstringIndex
	LastIssuedIndex int
	// Revocations list all revocations for this SubjectID
	Revocations []revocationRecord `gorm:"foreignKey:StatusListCredential;references:SubjectID"`
}

func (s revocationRecord) TableName() string {
	return "status_list_status"
}

// revocationRecord is created when a statusList entry has been revoked.
type revocationRecord struct {
	// StatusListCredential is the credentialSubject.ID this revocation belongs to. Example https://example.com/iam/id/statuslist/1
	StatusListCredential string `gorm:"primaryKey"`
	// StatusListIndex of the revoked status list entry. Range: 0 <= StatusListIndex <= statuslist2021.MaxBitstringIndex
	StatusListIndex int `gorm:"primaryKey;autoIncrement:false"`
	// CredentialID is the VC.ID of the credential revoked by this status list entry.
	// The value is stored as convenience during revocation, but is not validated.
	// Example did:web:example.com:iam:id#unique-identifier
	CredentialID string
	// RevokedAt contains the UNIX timestamp the revocation was registered.
	RevokedAt int64 `gorm:"autoCreateTime;column:created_at"`
}

var _ StatusList2021Issuer = (*sqlStore)(nil)

type sqlStore struct {
	db        *gorm.DB
	writeLock sync.Mutex
}

// DB creates a new Session with the provided context.
func (s *sqlStore) DB(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx)
}

func NewStatusListStore(db *gorm.DB) (*sqlStore, error) {
	return &sqlStore{db: db}, nil
}

func (s *sqlStore) CredentialSubject(ctx context.Context, issuer did.DID, page int) (*StatusList2021CredentialSubject, error) {
	statusListCredential, err := toStatusListCredential(issuer, page)
	if err != nil {
		return nil, err
	}

	// Check that status_list_credential exists! and then load all revocations.
	var statuslist statusListCredentialRecord
	err = s.DB(ctx).Preload("Revocations").First(&statuslist, "subject_id = ?", statusListCredential).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// status_list_credential.id does not exist or is not managed by this node
			return nil, errNotFound
		}
		return nil, err
	}

	// make encodedList
	bitstring := NewBitstring()
	for _, rev := range statuslist.Revocations {
		if err = bitstring.SetBit(rev.StatusListIndex, true); err != nil {
			// can't happen
			return nil, err
		}
	}
	encodedList, err := Compress(*bitstring)
	if err != nil {
		// can't happen
		return nil, err
	}

	// return credential subject
	return &StatusList2021CredentialSubject{
		Id:            statusListCredential,
		Type:          StatusList2021CredentialSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodedList,
	}, nil
}

func (s *sqlStore) Create(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*StatusList2021Entry, error) {
	if purpose != StatusPurposeRevocation {
		return nil, errUnsupportedPurpose
	}

	if _, isSQLite := s.db.Config.Dialector.(*sqlite.Dialector); isSQLite {
		// SQLite does not support SELECT FOR UPDATE and allows only 1 active write transaction at any time,
		// and any other attempt to acquire a write transaction will directly return an error.
		// This is in contrast to most other SQL-databases, which let the 2nd thread wait for some time to acquire the lock.
		// The general advice for SQLite is to retry the operation, which is just poor-man's scheduling.
		// So to keep behavior consistent across databases, we'll just lock the entire store for the duration of the transaction.
		// See https://github.com/nuts-foundation/nuts-node/pull/2589#discussion_r1399130608
		s.writeLock.Lock()
		defer s.writeLock.Unlock()
	}

	var credentialRecord statusListCredentialRecord
	for {
		err := s.DB(ctx).Transaction(func(tx *gorm.DB) error {
			// lock issuer's last page; iff it exists
			//
			// SELECT *
			// FROM status_list_credential
			// WHERE issuer = 'issuer.String()'
			// ORDER BY page DESC
			// LIMIT 1
			// FOR UPDATE;
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Order("page").
				Last(&credentialRecord, "issuer = ?", issuer.String()).
				Error
			if err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}

				// first time issuer; prepare to create a new Page / StatusListCredential
				credentialRecord = statusListCredentialRecord{
					Issuer:          issuer.String(),
					LastIssuedIndex: MaxBitstringIndex, // this will be incremented to move to page 1
					Page:            0,
				}
			}

			// next index
			credentialRecord.LastIssuedIndex++

			// create new page (statusListCredential) if current is full
			if credentialRecord.LastIssuedIndex > MaxBitstringIndex {
				credentialRecord.LastIssuedIndex = 0
				credentialRecord.Page++

				// set statusListCredential with correct page
				credentialRecord.SubjectID, err = toStatusListCredential(issuer, credentialRecord.Page)
				if err != nil {
					return err
				}

				// add new statusListCredential
				// this is not protected by the SELECT FOR UPDATE clause, so can fail with gorm.ErrDuplicatedKey
				//
				// INSERT INTO  status_list_credential (id, issuer, page, last_issued_index)
				// VALUES ('credentialRecord.ID', 'credentialRecord.Issuer', 'credentialRecord.Page', 0);
				return tx.Create(credentialRecord).Error
			}

			// update last_issued_index and release lock
			//
			// UPDATE status_list_credential
			// SET last_issued_index = 'credentialRecord.LastIssuedIndex'
			// WHERE id = 'credentialRecord.ID';
			return tx.Model(&statusListCredentialRecord{}).
				Where("subject_id = ?", credentialRecord.SubjectID).
				UpdateColumn("last_issued_index", credentialRecord.LastIssuedIndex).Error // only then update
		})
		if err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				// gorm.ErrDuplicatedKey means that a race condition occurred while trying to add a new statusListCredential.
				// This can't happen for SQLite due to the lock
				// manually check test "no race conditions on UPDATE or CREATE" if this logic changes.
				continue
			}
			return nil, err
		}
		break
	}

	return &StatusList2021Entry{
		ID:                   fmt.Sprintf("%s#%d", credentialRecord.SubjectID, credentialRecord.LastIssuedIndex),
		Type:                 StatusList2021EntryType,
		StatusPurpose:        StatusPurposeRevocation,
		StatusListIndex:      strconv.Itoa(credentialRecord.LastIssuedIndex),
		StatusListCredential: credentialRecord.SubjectID,
	}, nil
}

func (s *sqlStore) Revoke(ctx context.Context, credentialID ssi.URI, entry StatusList2021Entry) error {
	// parse StatusListIndex
	statusListIndex, err := strconv.Atoi(entry.StatusListIndex)
	if err != nil {
		return err
	}

	// validate StatusPurpose
	if entry.StatusPurpose != StatusPurposeRevocation {
		return errUnsupportedPurpose
	}

	// check if StatusList2021Credential is managed by this node
	var statuslist statusListCredentialRecord
	// SELECT * FROM status_list_credential WHERE id = 'entry.StatusListCredential' LIMIT 1;
	err = s.DB(ctx).First(&statuslist, "subject_id = ?", entry.StatusListCredential).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errNotFound // statusListCredential not managed by this node
		}
		return err
	}

	// validate StatusListIndex
	if statusListIndex < 0 || statusListIndex > statuslist.LastIssuedIndex {
		return ErrIndexNotInBitstring
	}

	// revoke
	revocation := revocationRecord{
		StatusListCredential: statuslist.SubjectID,
		StatusListIndex:      statusListIndex,
		CredentialID:         credentialID.String(),
	}
	// INSERT INTO status_list_status (status_list_credential, status_list_index, credentialID)
	// VALUES ('statuslist.ID', 'statusListIndex', 'credentialID.String()');
	err = s.DB(ctx).Create(&revocation).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return errRevoked // already revoked
		}
		return err
	}

	// successful revocation
	return nil
}

func toStatusListCredential(issuer did.DID, page int) (string, error) {
	switch issuer.Method {
	case "web":
		issuerAsURL, err := didweb.DIDToURL(issuer) // https://example.com/iam/id
		if err != nil {
			return "", err
		}
		return issuerAsURL.JoinPath("statuslist", strconv.Itoa(page)).String(), nil // https://example.com/iam/id/statuslist/page
	}
	return "", fmt.Errorf("status list: unsupported DID method: %s", issuer.Method)
}
