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

package issuer

import (
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/store"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var _ Store = &sqlStore{}

var _ schema.Tabler = &issuedCredential{}

type issuedCredential struct {
	ID         string                 `gorm:"primaryKey"`
	Credential store.CredentialRecord `gorm:"foreignKey:ID;references:ID"`
}

func (i issuedCredential) TableName() string {
	return "issued_credential"
}

type sqlStore struct {
	db *gorm.DB
}

func (s sqlStore) Diagnostics() []core.DiagnosticResult {
	// count number of issued credentials
	var count int64
	if err := s.db.Model(&issuedCredential{}).Count(&count).Error; err != nil {
		log.Logger().WithError(err).Error("Failed to count issued credentials")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "issued_credentials_count",
			Outcome: int(count),
		},
	}
}

func (s sqlStore) GetCredential(id ssi.URI) (*vc.VerifiableCredential, error) {
	record := &issuedCredential{}
	err := s.db.Model(&issuedCredential{}).
		Preload("Credential").
		First(record, "id = ?", id.String()).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, types.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return vc.ParseVerifiableCredential(record.Credential.Raw)
}

func (s sqlStore) StoreCredential(credential vc.VerifiableCredential) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		credentialRecord, err := store.CredentialStore{}.Store(tx, credential)
		if err != nil {
			return err
		}
		return tx.Create(&issuedCredential{
			ID:         credential.ID.String(),
			Credential: *credentialRecord,
		}).Error
	})
}

func (s sqlStore) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := map[string]string{
		"type":   credentialType.String(),
		"issuer": issuer.String(),
	}
	if subject != nil {
		query["credentialSubject.id"] = subject.String()
	}
	var records []issuedCredential
	err := store.CredentialStore{}.BuildSearchStatement(s.db, "issued_credential.id", query).
		Preload("Credential").
		Find(&records).Error
	if err != nil {
		return nil, err
	}
	credentials := make([]vc.VerifiableCredential, len(records))
	for i, record := range records {
		curr, err := vc.ParseVerifiableCredential(record.Credential.Raw)
		if err != nil {
			return nil, err
		}
		credentials[i] = *curr
	}
	return credentials, nil
}

func (s sqlStore) Close() error {
	// closed by storage module
	return nil
}

func (s sqlStore) StoreRevocation(_ credential.Revocation) error {
	return errors.New("StoreRevocation() not supported for SQL store")
}

func (s sqlStore) GetRevocation(_ ssi.URI) (*credential.Revocation, error) {
	return nil, types.ErrNotFound
}
