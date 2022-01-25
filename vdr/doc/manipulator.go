/*
 * Copyright (C) 2021 Nuts community
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

package doc

import (
	"errors"

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
func (u Manipulator) Deactivate(id did.DID) error {
	_, meta, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	// A deactivated DID resolves to an empty DID document.
	emptyDoc := CreateDocument()
	emptyDoc.ID = id
	return u.Updater.Update(id, meta.Hash, emptyDoc, nil)
}

// AddVerificationMethod adds a new key as a VerificationMethod to the document.
// The key is not used yet and should be manually added to one of the VerificationRelationships
func (u Manipulator) AddVerificationMethod(id did.DID) (*did.VerificationMethod, error) {
	doc, meta, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return nil, err
	}
	if meta.Deactivated {
		return nil, types.ErrDeactivated
	}
	method, err := CreateNewVerificationMethodForDID(doc.ID, u.KeyCreator)
	if err != nil {
		return nil, err
	}
	method.Controller = doc.ID
	doc.VerificationMethod.Add(method)
	if err = u.Updater.Update(id, meta.Hash, *doc, nil); err != nil {
		return nil, err
	}
	return method, nil
}

// RemoveVerificationMethod is a helper function to remove a verificationMethod from a DID Document
// When the verificationMethod is used in an assertion or authentication method, it is also removed there.
func (u Manipulator) RemoveVerificationMethod(id, keyID did.DID) error {
	doc, meta, err := u.Resolver.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	if meta.Deactivated {
		return types.ErrDeactivated
	}
	removedVM := doc.VerificationMethod.Remove(keyID)
	// Check if it is actually found and removed:
	if removedVM == nil {
		return errors.New("verificationMethod not found in document")
	}

	doc.CapabilityInvocation.Remove(keyID)
	doc.Authentication.Remove(keyID)
	doc.AssertionMethod.Remove(keyID)
	return u.Updater.Update(id, meta.Hash, *doc, nil)
}

// CreateNewVerificationMethodForDID creates a new VerificationMethod of type JsonWebKey2020
// with a freshly generated key for a given DID.
func CreateNewVerificationMethodForDID(id did.DID, keyCreator nutsCrypto.KeyCreator) (*did.VerificationMethod, error) {
	key, err := keyCreator.New(didSubKIDNamingFunc(id))
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

// getVerificationMethodDiff is a helper function that makes a diff of verificationMethods between
// a provided current and a proposedDocument. It returns a list with new and removed verificationMethods
func getVerificationMethodDiff(currentDocument, proposedDocument did.Document) (new, removed []*did.VerificationMethod) {
	for _, vmp := range proposedDocument.VerificationMethod {
		found := false
		for _, mpc := range currentDocument.VerificationMethod {
			if vmp.ID.Equals(mpc.ID) {
				found = true
				break
			}
		}
		if !found {
			new = append(new, vmp)
		}
	}
	// check which are not present in the proposed document
	for _, vmc := range currentDocument.VerificationMethod {
		found := false
		for _, vmp := range proposedDocument.VerificationMethod {
			if vmp.ID.Equals(vmc.ID) {
				found = true
				break
			}
		}
		if !found {
			removed = append(removed, vmc)
		}
	}
	return
}
