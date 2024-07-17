/*
 * Copyright (C) 2023 Nuts community
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

package didweb

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"gorm.io/gorm"
)

var _ didsubject.MethodManager = (*Manager)(nil)

// NewManager creates a new Manager to create and update did:web DID documents.
func NewManager(rootDID did.DID, tenantPath string, keyStore nutsCrypto.KeyStore, db *gorm.DB) *Manager {
	return &Manager{
		db:         db,
		rootDID:    rootDID,
		tenantPath: tenantPath,
		keyStore:   keyStore,
	}
}

// Manager creates and updates did:web documents
type Manager struct {
	db         *gorm.DB
	rootDID    did.DID
	keyStore   nutsCrypto.KeyStore
	tenantPath string
}

func (m Manager) NewDocument(ctx context.Context, keyFlags didsubject.DIDKeyFlags) (*didsubject.DIDDocument, error) {
	newDID, _ := did.ParseDID(fmt.Sprintf("%s:%s:%s", m.rootDID.String(), m.tenantPath, uuid.New()))
	var sqlVerificationMethods []didsubject.VerificationMethod

	keyTypes := []didsubject.DIDKeyFlags{didsubject.AssertionKeyUsage(), didsubject.EncryptionKeyUsage()}
	for _, keyType := range keyTypes {
		if keyType.Is(keyFlags) {
			verificationMethod, err := m.NewVerificationMethod(ctx, *newDID, keyType)
			if err != nil {
				return nil, err
			}
			asJson, _ := json.Marshal(verificationMethod)
			sqlVerificationMethods = append(sqlVerificationMethods, didsubject.VerificationMethod{
				ID:       verificationMethod.ID.String(),
				KeyTypes: didsubject.VerificationMethodKeyType(keyType),
				Data:     asJson,
			})
		}
	}

	// Create sql.DIDDocument
	now := time.Now().Unix()
	sqlDoc := didsubject.DIDDocument{
		DID: didsubject.DID{
			ID: newDID.String(),
		},
		CreatedAt:           now,
		UpdatedAt:           now,
		Version:             0,
		VerificationMethods: sqlVerificationMethods,
	}

	return &sqlDoc, nil
}

func (m Manager) NewVerificationMethod(ctx context.Context, controller did.DID, keyUsage didsubject.DIDKeyFlags) (*did.VerificationMethod, error) {
	var err error
	var verificationMethodKey nutsCrypto.Key
	verificationMethodID := did.DIDURL{
		DID:      controller,
		Fragment: uuid.New().String(),
	}
	if keyUsage.Is(didsubject.KeyAgreementUsage) {
		return nil, errors.New("key agreement not supported for did:web")
		// todo requires update to nutsCrypto module
		//verificationMethodKey, err = m.keyStore.NewRSA(ctx, func(key crypt.PublicKey) (string, error) {
		//	return verificationMethodID.String(), nil
		//})
	} else {
		verificationMethodKey, err = m.keyStore.New(ctx, func(key crypto.PublicKey) (string, error) {
			return verificationMethodID.String(), nil
		})
	}
	if err != nil {
		return nil, err
	}
	verificationMethod, err := did.NewVerificationMethod(verificationMethodID, ssi.JsonWebKey2020, controller, verificationMethodKey.Public())
	if err != nil {
		return nil, err
	}
	return verificationMethod, nil
}

// Commit does nothing for did:web. This is important since only the one of the method managers may have a failing commit.
// This is a poor-mans 2-phase commit.
func (m Manager) Commit(_ context.Context, _ didsubject.DIDChangeLog) error {
	return nil
}

// IsCommitted always returns true for did:web. did:web gets its state from the primary DB.
func (m Manager) IsCommitted(_ context.Context, _ didsubject.DIDChangeLog) (bool, error) {
	return true, nil
}
