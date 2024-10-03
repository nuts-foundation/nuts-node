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
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// statusListValidity is default validity of a StatusList2021Credential
const statusListValidity = 24 * time.Hour // TODO: make configurable, and set reasonable default.
// minTimeUntilExpired is the minimum time a StatusList2021Credential must be valid that is returned by the API
const minTimeUntilExpired = statusListValidity / 4

func (s credentialIssuerRecord) TableName() string {
	return "status_list"
}

// credentialIssuerRecord keeps track of a StatusList2021Credential issued by the Issuer, and what the LastIssuedIndex is for the StatusList2021Credential.
// Issuers can have multiple StatusList2021Credentials, the one with the highest page number is the most recent VC / VC currently being issued on.
type credentialIssuerRecord struct {
	// SubjectID is the VC.credentialSubject.ID for this StatusListCredential.
	// It is the URL where the StatusList2021Credential can be downloaded e.g., https://example.com/iam/id/statuslist/1.
	SubjectID string `gorm:"primaryKey"`
	// Issuer of the StatusListCredential.
	Issuer string
	// Page number corresponding to this SubjectID.
	Page int
	// LastIssuedIndex on this page. Range:  0 <= StatusListIndex < maxBitstringIndex
	LastIssuedIndex int
	// Revocations list all revocations for this SubjectID
	Revocations []revocationRecord `gorm:"foreignKey:StatusListCredential;references:SubjectID"`
}

func (c credentialRecord) TableName() string {
	return "status_list_credential"
}

// credentialRecord contains the latest known version of a StatusList2021Credential.
// For managed StatusList2021Credentials this always contains the most up-to-date information,
// for external StatusList2021Credentials it contains the status as received on CreatedAt.
type credentialRecord struct {
	// SubjectID is the URL (from StatusList2021Entry.StatusListCredential) that credential was downloaded from
	// it should match with CredentialSubject.ID
	SubjectID string `gorm:"primaryKey"`
	// StatusPurpose is the purpose listed in the StatusList2021Credential.credentialSubject
	StatusPurpose string
	// Bitstring is the expanded StatusList2021 bitstring
	Bitstring bitstring
	// CreatedAt is the UNIX timestamp this credentialRecord was generated
	CreatedAt int64 `gorm:"autoCreateTime"`
	// Expires is the UNIX timestamp the StatusList2021Credential expires. May be missing in external StatusList2021Credentials
	Expires *int64
	// Raw contains the raw data of the Verifiable Credential
	Raw string
}

func (s revocationRecord) TableName() string {
	return "status_list_entry"
}

// revocationRecord is created when a statusList entry has been revoked.
type revocationRecord struct {
	// StatusListCredential is the credentialSubject.ID this revocation belongs to. Example https://example.com/iam/id/statuslist/1
	StatusListCredential string `gorm:"primaryKey"`
	// StatusListIndex of the revoked status list entry. Range: 0 <= StatusListIndex <= maxBitstringIndex
	StatusListIndex int `gorm:"primaryKey;autoIncrement:false"`
	// CredentialID is the VC.ID of the credential revoked by this status list entry.
	// The value is stored as convenience during revocation, but is not validated.
	// Example did:web:example.com:iam:id#unique-identifier
	CredentialID string
	// RevokedAt contains the UNIX timestamp the revocation was registered.
	RevokedAt int64 `gorm:"autoCreateTime;column:created_at"`
}

func (cs *StatusList2021) loadCredential(subjectID string) (*credentialRecord, error) {
	cr := new(credentialRecord)
	err := cs.db.First(cr, "subject_id = ?", subjectID).Error
	if err != nil {
		return nil, err
	}
	return cr, nil
}

// isManaged returns true if the StatusList2021Credential is issued by this node.
// returns false on db errors, or if the StatusList2021Credential does not exist.
func (cs *StatusList2021) isManaged(subjectID string) bool {
	var exists bool
	cs.db.Model(new(credentialIssuerRecord)).
		Select("count(*) > 0").
		Group("subject_id").
		Where("subject_id = ?", subjectID).
		First(&exists)
	return exists
}

func (cs *StatusList2021) Credential(ctx context.Context, issuerDID did.DID, page int) (*vc.VerifiableCredential, error) {
	statusListCredentialURL := cs.statusListURL(issuerDID, page)

	// only return StatusList2021Credential if it already exists, and we are the issuer
	if !cs.isManaged(statusListCredentialURL) {
		return nil, errNotFound
	}

	// return stored StatusList2021Credential if valid for long enough
	credRecord, err := cs.loadCredential(statusListCredentialURL)
	if err == nil && time.Now().Add(minTimeUntilExpired).Before(time.Unix(*credRecord.Expires, 0)) {
		cred, err := vc.ParseVerifiableCredential(credRecord.Raw)
		if err == nil {
			return cred, nil
		}
		// log broken StatusList2021Credential in DB and try to issue a new one
		log.Logger().WithError(err).WithField("StatusList2021Credential", statusListCredentialURL).Error("Failed to parse managed StatusList2021Credential in database")
	}

	// Rewrite audit context. This is a system action and should not be logged against an external party.
	info := audit.InfoFromContext(ctx)
	if info != nil {
		module, operation, ok := strings.Cut(info.Operation, ".")
		if ok {
			ctx = audit.Context(ctx, "_system_signing_expired_statuslist2021credential", module, operation)
		}
	}

	// resolve signing key outside of transaction
	kid, _, err := cs.ResolveKey(issuerDID, nil, resolver.AssertionMethod)
	if err != nil {
		// should never happen; credential confirmed to issued by this node
		return nil, err
	}

	// issue a new StatusList2021Credential if we can't load the existing, or it's about to expire
	var cred *vc.VerifiableCredential // is nil, so if this panics outside this method the var name is probably shadowed in the db.Transaction.
	err = cs.db.Transaction(func(tx *gorm.DB) error {
		// lock credentialRecord row for statusListCredentialURL since it will be updated.
		// Revoke does the same to guarantee the DB always contains all revocations.
		// Microsoft SQL server does not support the locking clause, so we have to use a raw query instead.
		// See https://github.com/nuts-foundation/nuts-node/issues/3393
		if tx.Dialector.Name() == "sqlserver" {
			err = tx.Raw("SELECT * FROM status_list_entry WITH (UPDLOCK, ROWLOCK) WHERE subject_id = ?", statusListCredentialURL).
				Scan(new(credentialRecord)).
				Error
		} else {
			err = tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
				Find(new(credentialRecord), "subject_id = ?", statusListCredentialURL).
				Error
		}
		if err != nil {
			return err
		}

		issuerRecord := new(credentialIssuerRecord)
		err = tx.Preload("Revocations").First(issuerRecord, "subject_id = ?", statusListCredentialURL).Error
		if err != nil {
			// gorm.ErrRecordNotFound can't happen, isManaged() confirmed it exists
			return err
		}
		transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
		cred, credRecord, err = cs.updateCredential(transactionContext, issuerRecord, kid)
		if err != nil {
			return err
		}

		err = tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(credRecord).Error
		if err != nil {
			// log error, but don't fail.
			log.Logger().
				WithError(err).
				WithField("Status list URL", statusListCredentialURL).
				Error("failed to store issued StatusList2021Credential")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return cred, nil
}

// updateCredential creates a signed StatusList2021Credential and a credentialRecord from the credentialIssuerRecord.
// All revocations must be present in the issuerRecord. The caller is responsible for writing the credentialRecord to the db.
func (cs *StatusList2021) updateCredential(ctx context.Context, issuerRecord *credentialIssuerRecord, kid string) (*vc.VerifiableCredential, *credentialRecord, error) {
	issuerDID, err := did.ParseDID(issuerRecord.Issuer)
	if err != nil {
		return nil, nil, err
	}

	// bit string
	expanded := newBitstring()
	for _, rev := range issuerRecord.Revocations {
		if err = expanded.setBit(rev.StatusListIndex, true); err != nil {
			// can't happen
			return nil, nil, err
		}
	}
	encodedList, err := compress(*expanded)
	if err != nil {
		// can't happen
		return nil, nil, err
	}

	// credential subject
	credSubject := &StatusList2021CredentialSubject{
		ID:            issuerRecord.SubjectID,
		Type:          StatusList2021CredentialSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodedList,
	}
	// create and sign a new StatusList2021Credential
	statusListCredential, err := cs.buildAndSignVC(ctx, *issuerDID, *credSubject, kid)
	if err != nil {
		return nil, nil, err
	}

	// create new credentialRecord
	expires := statusListCredential.ExpirationDate.Unix()
	credRecord := &credentialRecord{
		SubjectID:     credSubject.ID,
		StatusPurpose: credSubject.StatusPurpose,
		Bitstring:     *expanded,
		Expires:       &expires,
		Raw:           statusListCredential.Raw(),
	}
	return statusListCredential, credRecord, nil
}

// buildAndSignVC intends to do the same as vcr.issuer.buildAndSignVC
func (cs *StatusList2021) buildAndSignVC(ctx context.Context, issuerDID did.DID, credSubject StatusList2021CredentialSubject, kid string) (*vc.VerifiableCredential, error) {
	iss := time.Now()
	exp := iss.Add(statusListValidity)
	credentialID := ssi.MustParseURI(fmt.Sprintf("%s#%s", issuerDID.String(), uuid.New().String()))
	template := vc.VerifiableCredential{
		Context: []ssi.URI{
			vc.VCContextV1URI(),
			StatusList2021ContextURI,
		},
		Type: []ssi.URI{
			vc.VerifiableCredentialTypeV1URI(),
			statusList2021CredentialTypeURI,
		},
		ID:                &credentialID,
		CredentialSubject: []any{credSubject},
		Issuer:            issuerDID.URI(),
		IssuanceDate:      iss,
		ExpirationDate:    &exp,
	}

	// sign the StatusList2021Credential
	return cs.Sign(ctx, template, kid)
}

func (cs *StatusList2021) Entry(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*StatusList2021Entry, error) {
	if purpose != StatusPurposeRevocation {
		return nil, errUnsupportedPurpose
	}

	// resolve signing key outside of transaction
	kid, _, err := cs.ResolveKey(issuer, nil, resolver.AssertionMethod)
	if err != nil {
		return nil, err
	}

	credentialIssuer := new(credentialIssuerRecord)
	for {
		err := cs.db.Transaction(func(tx *gorm.DB) error {
			// Find issuer's last page; if it exists. Lock all pages.
			// Microsoft SQL server does not support the locking clause, so we have to use a raw query instead.
			// See https://github.com/nuts-foundation/nuts-node/issues/3393
			if tx.Dialector.Name() == "sqlserver" {
				var pages []credentialIssuerRecord
				if err = tx.Raw("SELECT * FROM status_list WITH (UPDLOCK, ROWLOCK) WHERE issuer = ?", issuer.String()).
					Scan(&pages).
					Error; err != nil {
					return err
				}
				if len(pages) == 0 {
					// mimic non-SQL Server behavior
					err = gorm.ErrRecordNotFound
				} else {
					// get last page, order by page first
					slices.SortFunc(pages, func(i, j credentialIssuerRecord) int {
						return i.Page - j.Page
					})
					credentialIssuer = &pages[len(pages)-1]
				}
			} else {
				err = tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
					Order("page").
					Last(credentialIssuer, "issuer = ?", issuer.String()).
					Error
			}
			if err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}

				// first time issuer; prepare to create a new Page / StatusListCredential
				credentialIssuer = &credentialIssuerRecord{
					Issuer:          issuer.String(),
					LastIssuedIndex: maxBitstringIndex, // this will be incremented to move to page 1
					Page:            0,
				}
			}

			// next index
			credentialIssuer.LastIssuedIndex++

			// create new page (statusListCredential) if current is full and release lock
			// write actions here are not protected by the SELECT FOR UPDATE clause, so can fail with gorm.ErrDuplicatedKey
			if credentialIssuer.LastIssuedIndex > maxBitstringIndex {
				credentialIssuer.LastIssuedIndex = 0
				credentialIssuer.Page++
				credentialIssuer.SubjectID = cs.statusListURL(issuer, credentialIssuer.Page)
				// add new credentialIssuerRecord
				if err = tx.Create(credentialIssuer).Error; err != nil {
					return err
				}

				// store transaction context
				transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
				_, credRecord, err := cs.updateCredential(transactionContext, credentialIssuer, kid)
				if err != nil {
					return err
				}
				return tx.Create(credRecord).Error
			}

			// update last_issued_index and release lock
			return tx.Model(&credentialIssuerRecord{}).
				Where("subject_id = ?", credentialIssuer.SubjectID).
				UpdateColumn("last_issued_index", credentialIssuer.LastIssuedIndex).Error // only then update
		})
		if err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				// gorm.ErrDuplicatedKey means that a race condition occurred while trying to add a new credentialRecord
				// or credentialIssuerRecord. We just have to try again.
				continue
			}
			return nil, err
		}
		break
	}

	return &StatusList2021Entry{
		ID:                   fmt.Sprintf("%s#%d", credentialIssuer.SubjectID, credentialIssuer.LastIssuedIndex),
		Type:                 StatusList2021EntryType,
		StatusPurpose:        StatusPurposeRevocation,
		StatusListIndex:      strconv.Itoa(credentialIssuer.LastIssuedIndex),
		StatusListCredential: credentialIssuer.SubjectID,
	}, nil
}

func (cs *StatusList2021) Revoke(ctx context.Context, credentialID ssi.URI, entry StatusList2021Entry) error {
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
	if !cs.isManaged(entry.StatusListCredential) {
		return errNotFound
	}

	// resolve signing key outside of transaction
	var issuerStr string
	err = cs.db.Model(&credentialIssuerRecord{}).Select("issuer").First(&issuerStr, "subject_id = ?", entry.StatusListCredential).Error
	if err != nil {
		// can't happen; confirmed isManaged
		return err
	}
	issuerDID, err := did.ParseDID(issuerStr)
	if err != nil {
		// can't happen; own DB
		return err
	}
	kid, _, err := cs.ResolveKey(*issuerDID, nil, resolver.AssertionMethod)
	if err != nil {
		// can't happen; credential confirmed to issued by this node
		return err
	}

	return cs.db.Transaction(func(tx *gorm.DB) error {
		// lock relevant credentialRecord. It was created when the first entry was issued for this StatusList2021Credential.
		err = tx.Model(new(credentialRecord)).
			Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("count(*) > 0").
			Group("subject_id").
			Where("subject_id = ?", entry.StatusListCredential).
			First(new(bool)).
			Error
		if err != nil {
			return err
		}

		// revoke
		revocation := revocationRecord{
			StatusListCredential: entry.StatusListCredential,
			StatusListIndex:      statusListIndex,
			CredentialID:         credentialID.String(),
		}

		// fail fast, immediately fail if revocation already exists
		err = tx.Create(&revocation).Error
		if err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return errRevoked // already revoked
			}
			return err
		}

		// load all revocations
		issuerRecord := new(credentialIssuerRecord)
		err = tx.Preload("Revocations").First(issuerRecord, "subject_id = ?", entry.StatusListCredential).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// can't happen, already checked
				return errNotFound
			}
			return err
		}

		// validate StatusListIndex; triggers a rollback after the fact, but this should never happen.
		if statusListIndex < 0 || statusListIndex > issuerRecord.LastIssuedIndex {
			return ErrIndexNotInBitstring
		}

		// append new revocation and re-issue the StatusList2021Credential.
		transactionContext := context.WithValue(ctx, storage.TransactionKey{}, tx)
		_, credRecord, err := cs.updateCredential(transactionContext, issuerRecord, kid)
		if err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(credRecord).Error
	})
}

func (cs *StatusList2021) statusListURL(issuer did.DID, page int) string {
	// https://example.com/statuslist/<did>/page
	result, _ := url.Parse(cs.baseURL)
	return result.JoinPath("statuslist", issuer.String(), strconv.Itoa(page)).String()
}
