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
 */

package didservice

import (
	"context"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Manipulator contains helper methods to update a Nuts DID document.
type Manipulator struct {
	// KeyCreator is used for getting a fresh key and use it to generate the Nuts DID
	KeyCreator nutsCrypto.KeyCreator
	// Updater is used for updating DID documents after the operation has been performed
	Updater types.DocUpdater
	// Resolver is used for resolving DID Documents
	Resolver types.DocResolver
}

// Deactivate updates the DID Document so it can no longer be updated
// It removes key material, services and controllers.
func (u Manipulator) Deactivate(ctx context.Context, id did.DID) error {
	_, _, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	// A deactivated DID resolves to an empty DID document.
	emptyDoc := CreateDocument()
	emptyDoc.ID = id
	return u.Updater.Update(ctx, id, emptyDoc)
}

// AddVerificationMethod adds a new key as a VerificationMethod to the document.
// The key is added to the VerficationMethod relationships specified by keyUsage.
func (u Manipulator) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage types.DIDKeyFlags) (*did.VerificationMethod, error) {
	doc, meta, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return nil, err
	}
	if meta.Deactivated {
		return nil, types.ErrDeactivated
	}
	method, err := CreateNewVerificationMethodForDID(ctx, doc.ID, u.KeyCreator)
	if err != nil {
		return nil, err
	}
	method.Controller = doc.ID
	doc.VerificationMethod.Add(method)
	applyKeyUsage(doc, method, keyUsage)
	if err = u.Updater.Update(ctx, id, *doc); err != nil {
		return nil, err
	}
	return method, nil
}

// RemoveVerificationMethod is a helper function to remove a verificationMethod from a DID Document
func (u Manipulator) RemoveVerificationMethod(ctx context.Context, id, keyID did.DID) error {
	doc, meta, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	if meta.Deactivated {
		return types.ErrDeactivated
	}
	lenBefore := len(doc.VerificationMethod)
	doc.RemoveVerificationMethod(keyID)
	if lenBefore == len(doc.VerificationMethod) {
		// do not update if nothing has changed
		return nil
	}

	return u.Updater.Update(ctx, id, *doc)
}

// CreateNewVerificationMethodForDID creates a new VerificationMethod of type JsonWebKey2020
// with a freshly generated key for a given DID.
func CreateNewVerificationMethodForDID(ctx context.Context, id did.DID, keyCreator nutsCrypto.KeyCreator) (*did.VerificationMethod, error) {
	key, err := keyCreator.New(ctx, didSubKIDNamingFunc(id))
	if err != nil {
		return nil, err
	}
	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, err
	}
	method, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, id, key.Public())
	if err != nil {
		return nil, err
	}
	return method, nil
}
