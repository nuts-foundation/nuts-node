package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// NutsDocCreator implements the DocCreator interface and can create Nuts DID Documents.
type NutsDocUpdater struct {
	// keyCreator is used for getting a fresh key and use it to generate the Nuts DID
	keyCreator nutsCrypto.KeyCreator
	keyStore   nutsCrypto.PublicKeyStore
}

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
		thumbprint, err := jwKey.Thumbprint(thumbprintAlg)
		if err != nil {
			return "", err
		}

		existingDID.Fragment = string(thumbprint)

		return existingDID.String(), nil
	}
}

// AddNewAuthenticationMethodToDIDDocument creates a new VerificationMethod of type JsonWebKey2020 with a freshly generated
func (u NutsDocUpdater) AddNewAuthenticationMethodToDIDDocument(doc *did.Document) error {
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

// getVerificationmethodDiff makes a diff of verificationMethods and returns a list with new and removed verificationMethods
func (u NutsDocUpdater) getVerificationMethodDiff(currentDocument,  proposedDocument *did.Document) (new, removed []*did.VerificationMethod) {
	for _, vmp := range proposedDocument.VerificationMethod {
		found := false
		for _, mpc := range currentDocument.VerificationMethod {
			if vmp.ID.Equals(mpc.ID) {
				found = true
				continue
			}
		}
		if !found {
			new = append(new, vmp)
		}
	}
	for _, vmc := range currentDocument.VerificationMethod {
		found := false
		for _, vmp := range proposedDocument.VerificationMethod {
			if vmp.ID.Equals(vmc.ID) {
				found = true
				continue
			}
		}
		if !found {
			removed = append(new, vmc)
		}
	}
	return
}


func (u NutsDocUpdater) RemoveVerificationMethod(keyID did.DID, document *did.Document, updateTime time.Time) error {
	var newVerificationMethods []*did.VerificationMethod
	var keysToRemove []*did.VerificationMethod
	for _, vm := range document.VerificationMethod {
		if vm.ID.Equals(keyID) {
			keysToRemove = append(keysToRemove, vm)
		} else {
			newVerificationMethods = append(newVerificationMethods, vm)
		}
	}
	for _, vm := range keysToRemove {
		u.keyStore.RevokePublicKey(vm.ID.String(), updateTime)
	}
	document.VerificationMethod = newVerificationMethods
	return nil
}
