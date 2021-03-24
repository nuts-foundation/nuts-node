package vdr

import (
	"crypto"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"

	"github.com/lestrrat-go/jwx/jwk"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// NutsDocUpdater contains helper methods to update a nuts document.
type NutsDocUpdater struct {
	// KeyCreator is used for getting a fresh key and use it to generate the Nuts DID
	KeyCreator nutsCrypto.KeyCreator
	VDR        types.VDR
}

// Deactivate updates the DID Document so it can no longer be updated
func (u NutsDocUpdater) Deactivate(id did.DID) error {
	_, meta, err := u.VDR.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return err
	}
	// A deactivated DID resolves to an empty DID document.
	emptyDoc := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      id,
	}
	return u.VDR.Update(id, meta.Hash, emptyDoc, nil)
}

func (u NutsDocUpdater) AddKey(id did.DID) (*did.VerificationMethod, error) {
	doc, meta, err := u.VDR.Resolve(id, &types.ResolveMetadata{AllowDeactivated: true})
	if err != nil {
		return nil, err
	}
	if meta.Deactivated {
		return nil, types.ErrDeactivated
	}
	updater := NutsDocUpdater{KeyCreator: u.KeyCreator}
	method, err := updater.CreateNewAuthenticationMethodForDID(doc.ID)
	if err != nil {
		return nil, err
	}
	method.Controller = doc.ID
	doc.VerificationMethod.Add(method)
	if err = u.VDR.Update(id, meta.Hash, *doc, nil); err != nil {
		return nil, err
	}
	return method, nil
}

// CreateNewAuthenticationMethodForDID creates a new VerificationMethod of type JsonWebKey2020 with a freshly generated key
// and adds it to the provided document
// FIXME:This method is a bit too high level and should be moved as part of this issue:
// https://github.com/nuts-foundation/nuts-node/issues/123
func (u NutsDocUpdater) CreateNewAuthenticationMethodForDID(id did.DID) (*did.VerificationMethod, error) {
	key, keyIDStr, err := u.KeyCreator.New(newNamingFnForExistingDID(id))
	if err != nil {
		return nil, err
	}
	keyID, err := did.ParseDID(keyIDStr)
	if err != nil {
		return nil, err
	}
	method, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key)
	if err != nil {
		return nil, err
	}
	return method, nil
}

// newNamingFnForExistingDID returns a KIDNamingFunc that can be used as param in the KeyCreator.New function.
// It wraps the KIDNamingFunc with the context of the DID of the document.
// It returns a keyID in the form of the documents DID with the new keys thumbprint as fragment.
func newNamingFnForExistingDID(existingDID did.DID) nutsCrypto.KIDNamingFunc {
	return func(pKey crypto.PublicKey) (string, error) {
		jwKey, err := jwk.New(pKey)
		if err != nil {
			return "", err
		}
		err = jwk.AssignKeyID(jwKey)
		if err != nil {
			return "", err
		}

		existingDID.Fragment = jwKey.KeyID()

		return existingDID.String(), nil
	}
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

// RemoveVerificationMethod is a helper function to remove a verificationMethod from a DID Document
// When the verificationMethod is used in an assertion or authentication method, it is also removed there.
func (u NutsDocUpdater) RemoveVerificationMethod(keyID did.DID, document *did.Document) error {
	removedVM := document.VerificationMethod.Remove(keyID)
	// Check if it is actually found and removed:
	if removedVM == nil {
		return errors.New("verificationMethod not found in document")
	}

	document.Authentication.Remove(keyID)
	document.AssertionMethod.Remove(keyID)

	return nil
}
