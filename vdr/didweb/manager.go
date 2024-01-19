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
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"net/url"
)

var _ management.DocumentManager = (*Manager)(nil)

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
func (m Manager) Create(ctx context.Context, _ management.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	return m.create(ctx, uuid.NewString())
}

func (m Manager) create(ctx context.Context, mostSignificantBits string) (*did.Document, crypto.Key, error) {
	newDID, err := URLToDID(*m.baseURL.JoinPath(mostSignificantBits))
	if err != nil {
		return nil, nil, err
	}
	verificationMethodKey, verificationMethod, err := m.createVerificationMethod(ctx, *newDID)
	if err != nil {
		return nil, nil, err
	}
	if err := m.store.create(*newDID, *verificationMethod); err != nil {
		return nil, nil, fmt.Errorf("store new DID: %w", err)
	}

	document := buildDocument(*newDID, []did.VerificationMethod{*verificationMethod})
	return &document, verificationMethodKey, nil
}

func (m Manager) createVerificationMethod(ctx context.Context, ownerDID did.DID) (crypto.Key, *did.VerificationMethod, error) {
	verificationMethodID := did.DIDURL{
		DID:      ownerDID,
		Fragment: "0", // TODO: Which fragment should we use? Thumbprint, UUID, index, etc...
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

// Resolve returns the did:web document for the given DID, if it is managed by this node.
func (m Manager) Resolve(id did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	vms, err := m.store.get(id)
	if err != nil {
		return nil, nil, err
	}
	document := buildDocument(id, vms)
	return &document, &resolver.DocumentMetadata{}, nil
}

func (m Manager) IsOwner(_ context.Context, id did.DID) (bool, error) {
	_, err := m.store.get(id)
	if errors.Is(err, resolver.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (m Manager) ListOwned(_ context.Context) ([]did.DID, error) {
	return m.store.list()
}

func buildDocument(subject did.DID, verificationMethods []did.VerificationMethod) did.Document {
	var vms []*did.VerificationMethod
	for _, verificationMethod := range verificationMethods {
		vms = append(vms, &verificationMethod)
	}

	document := did.Document{
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID: subject,
	}
	for _, verificationMethod := range verificationMethods {
		document.AddAssertionMethod(&verificationMethod)
		document.AddAuthenticationMethod(&verificationMethod)
		document.AddKeyAgreement(&verificationMethod)
		document.AddCapabilityDelegation(&verificationMethod)
		document.AddCapabilityInvocation(&verificationMethod)
	}
	return document
}
