/*
 * Nuts node
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"

	ssi "github.com/nuts-foundation/go-did"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/shengdoushi/base58"

	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// NutsDIDMethodName is the DID method name used by Nuts
const NutsDIDMethodName = "nuts"

// Creator implements the DocCreator interface and can create Nuts DID Documents.
type Creator struct {
	// KeyStore is used for getting a fresh key and use it to generate the Nuts DID
	KeyStore nutsCrypto.Accessor
}


// DefaultCreationOptions returns the default DIDCreationOptions: no controllers, CapablilityInvocation = true, AssertionMethod = true and SelfControl = true
func DefaultCreationOptions() vdr.DIDCreationOptions {
	return vdr.DIDCreationOptions{
		Controllers:           []did.DID{},
		AssertionMethod:       true,
		Authentication:        false,
		CapablilityDelegation: false,
		CapablilityInvocation: true,
		KeyAgreement:          false,
		SelfControl:           true,
	}
}

// didKIDNamingFunc is a function used to name a key used in newly generated DID Documents
func didKIDNamingFunc(pKey crypto.PublicKey) (string, error) {
	ecPKey, ok := pKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("could not generate kid: invalid key type")
	}

	if ecPKey.Curve == nil {
		return "", errors.New("could not generate kid: empty key curve")
	}

	// according to RFC006:
	// --------------------

	// generate idString
	pkBytes := elliptic.Marshal(ecPKey.Curve, ecPKey.X, ecPKey.Y)
	pkHash := sha256.Sum256(pkBytes)
	idString := base58.Encode(pkHash[:], base58.BitcoinAlphabet)

	// generate kid fragment
	jwKey, err := jwk.New(pKey)
	if err != nil {
		return "", err
	}
	err = jwk.AssignKeyID(jwKey)
	if err != nil {
		return "", err
	}

	// assemble
	kid := &did.DID{}
	kid.Method = NutsDIDMethodName
	kid.ID = idString
	kid.Fragment = jwKey.KeyID()

	return kid.String(), nil
}

// Create creates a Nuts DID Document with a valid DID id based on a freshly generated keypair.
// The key is added to the verificationMethod list and referred to from the Authentication list
// todo options validation
// todo return values
func (n Creator) Create(options vdr.DIDCreationOptions) (*did.Document, nutsCrypto.Accessor, string, crypto.PublicKey, error) {
	// First, generate a new keyPair with the correct kid
	keyStore := n.KeyStore
	if options.SelfControl {
		keyStore = nutsCrypto.NewEphemeralKeyStore()
	}

	publicKey, kidStr, err := keyStore.New(didKIDNamingFunc)
	if err != nil {
		return nil, nil, "", nil, err
	}
	keyID, err := did.ParseDID(kidStr)
	if err != nil {
		return nil, nil, "", nil, err
	}

	// The Document DID will be the keyIDStr without the fragment:
	didID := *keyID
	didID.Fragment = ""

	// create the bare document
	doc := &did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      didID,
	}

	var verificationMethod *did.VerificationMethod
	if options.SelfControl {
		// Add VerificationMethod using generated key
		verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, publicKey)
		if err != nil {
			return nil, nil, "", nil, err
		}
		// also set as controller
		doc.Controller = append(doc.Controller, didID)
	} else {
		// Generate new key for other key capabilities, store the private key
		capPub, capKidStr, err := n.KeyStore.New(didKIDNamingFunc)
		if err != nil {
			return nil, nil, "", nil, err
		}
		capKeyID, err := did.ParseDID(capKidStr)
		if err != nil {
			return nil, nil, "", nil, err
		}
		verificationMethod, err = did.NewVerificationMethod(*capKeyID, ssi.JsonWebKey2020, did.DID{}, capPub)
		if err != nil {
			return nil, nil, "", nil, err
		}
	}

	// set all methods
	if options.CapablilityDelegation {
		doc.AddCapabilityDelegation(verificationMethod)
	}
	if options.CapablilityInvocation {
		doc.AddCapabilityInvocation(verificationMethod)
	}
	if options.Authentication {
		doc.AddAuthenticationMethod(verificationMethod)
	}
	if options.AssertionMethod {
		doc.AddAssertionMethod(verificationMethod)
	}
	if options.KeyAgreement {
		doc.AddKeyAgreement(verificationMethod)
	}

	// controllers
	for _, c := range options.Controllers {
		doc.Controller = append(doc.Controller, c)
	}

	// return the doc and the keyCreator that created the private key
	return doc, keyStore, kidStr, publicKey, nil
}
