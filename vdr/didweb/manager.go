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
	crypt "crypto"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"gorm.io/gorm"
	"net/url"
)

var _ management.DocCreator = (*Manager)(nil)
var _ management.DocReader = (*Manager)(nil)

// NewManager creates a new Manager to create and update did:web DID documents.
func NewManager(baseURL url.URL, keyStore crypto.KeyStore, db *gorm.DB) *Manager {
	return &Manager{
		store:    &sqlStore{db: db},
		baseURL:  baseURL,
		keyStore: keyStore,
	}
}

// Manager creates and updates did:web documents
type Manager struct {
	baseURL  url.URL
	store    *sqlStore
	keyStore crypto.KeyStore
}

// Create creates a new did:web document.
func (m Manager) Create(ctx context.Context, method string, _ management.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	if method != MethodName {
		return nil, nil, fmt.Errorf("unsupported method: %s", method)
	}
	newDID, err := URLToDID(*m.baseURL.JoinPath(uuid.NewString()))
	if err != nil {
		return nil, nil, err
	}
	verificationMethodKey, verificationMethod, err := m.createVerificationMethod(ctx, *newDID)
	if err != nil {
		return nil, nil, err
	}
	if err := m.store.create(newDID.String(), *verificationMethod); err != nil {
		return nil, nil, fmt.Errorf("store new DID: %w", err)
	}

	document := buildDocument(*newDID, []did.VerificationMethod{*verificationMethod})
	return &document, verificationMethodKey, nil
}

func (m Manager) Read(id did.DID) (*did.Document, error) {
	verificationMethods, err := m.store.get(id.String())
	if err != nil {
		return nil, err
	}
	document := buildDocument(id, verificationMethods)
	return &document, nil
}

func (m Manager) createVerificationMethod(ctx context.Context, ownerDID did.DID) (crypto.Key, *did.VerificationMethod, error) {
	verificationMethodID := did.DIDURL{
		DID:      ownerDID,
		Fragment: "0",
	}
	verificationMethodKey, err := m.keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
		return verificationMethodID.String(), nil
	})
	if err != nil {
		return nil, nil, err
	}
	verificationMethod, err := did.NewVerificationMethod(verificationMethodID, ssi.JsonWebKey2020, ownerDID, verificationMethodKey.Public())
	if err != nil {
		return nil, nil, err
	}
	return verificationMethodKey, verificationMethod, nil
}

func buildDocument(subject did.DID, verificationMethods []did.VerificationMethod) did.Document {
	var vms []*did.VerificationMethod
	for _, verificationMethod := range verificationMethods {
		vms = append(vms, &verificationMethod)
	}
	var vmRelationships did.VerificationRelationships
	for _, verificationMethod := range verificationMethods {
		vmRelationships = append(vmRelationships, did.VerificationRelationship{VerificationMethod: &verificationMethod})
	}
	return did.Document{
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID:                   subject,
		VerificationMethod:   vms,
		Authentication:       vmRelationships,
		AssertionMethod:      vmRelationships,
		KeyAgreement:         vmRelationships,
		CapabilityInvocation: vmRelationships,
		CapabilityDelegation: vmRelationships,
	}
}
