package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"errors"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// NutsDocUpdater contains helper methods to update a nuts document.
type NutsDocUpdater struct {
	// keyCreator is used for getting a fresh key and use it to generate the Nuts DID
	keyCreator nutsCrypto.KeyCreator
}

// newNamingFnForExistingDID returns a KIDNamingFunc that can be used as param in the keyCreator.New function.
// It wraps the KIDNamingFunc with the context of the DID of the document.
// It returns a keyID in the form of the documents DID with the new keys thumbprint as fragment.
func newNamingFnForExistingDID(existingDID did.DID) nutsCrypto.KIDNamingFunc {
	return func(pKey crypto.PublicKey) (string, error) {
		ecPKey, ok := pKey.(*ecdsa.PublicKey)
		if !ok {
			return "", errors.New("could not generate kid: invalid key type")
		}

		if ecPKey.Curve == nil {
			return "", errors.New("could not generate kid: empty key curve")
		}

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

// RotateAuthenticationKey will create a new AuthenticationMethod with the document id as prefix
// It removes the old authenticationMethod from the document indicated with methodID
// It adds the new authenticationMethod to the document
// It requires the methodID to be part of the authenticationMethods
// FIXME:This method is a bit too high level and should be moved as part of this issue:
// https://github.com/nuts-foundation/nuts-node/issues/123
func (u NutsDocUpdater) RotateAuthenticationKey(methodID did.DID, doc *did.Document) error {
	if err := u.RemoveVerificationMethod(methodID, doc); err != nil {
		return err
	}

	if err := u.CreateNewAuthenticationMethodForDocument(doc); err != nil {
		return err
	}
	return nil
}

// CreateNewAuthenticationMethodForDocument creates a new VerificationMethod of type JsonWebKey2020 with a freshly generated key
// and adds it to the provided document
// FIXME:This method is a bit too high level and should be moved as part of this issue:
// https://github.com/nuts-foundation/nuts-node/issues/123
func (u NutsDocUpdater) CreateNewAuthenticationMethodForDocument(doc *did.Document) error {
	key, keyIDStr, err := u.keyCreator.New(newNamingFnForExistingDID(doc.ID))
	if err != nil {
		return err
	}
	keyID, err := did.ParseDID(keyIDStr)
	if err != nil {
		return err
	}
	method, err := did.NewVerificationMethod(*keyID, did.JsonWebKey2020, did.DID{}, key)
	if err != nil {
		return err
	}
	doc.AddAuthenticationMethod(method)
	return nil
}

// getVerificationMethodDiff is a helper function that makes a diff of verificationMethods between
// a provided current and a proposedDocument. It returns a list with new and removed verificationMethods
func getVerificationMethodDiff(currentDocument, proposedDocument did.Document) (new, removed []*did.VerificationMethod) {
	for _, vmp := range proposedDocument.VerificationMethod {
		for _, mpc := range currentDocument.VerificationMethod {
			if vmp.ID.Equals(mpc.ID) {
				goto nextProposedMethod
			}
		}
		new = append(new, vmp)
		nextProposedMethod:
	}
	// check which are not present in the proposed document
	for _, vmc := range currentDocument.VerificationMethod {
		for _, vmp := range proposedDocument.VerificationMethod {
			if vmp.ID.Equals(vmc.ID) {
				goto nextCurrentMethod
			}
		}
		removed = append(removed, vmc)
		nextCurrentMethod:
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
