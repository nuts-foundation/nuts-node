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
	KeyStore nutsCrypto.KeyCreator
}

// DefaultCreationOptions returns the default DIDCreationOptions: no controllers, CapabilityInvocation = true, AssertionMethod = true and SelfControl = true
func DefaultCreationOptions() vdr.DIDCreationOptions {
	return vdr.DIDCreationOptions{
		Controllers:          []did.DID{},
		AssertionMethod:      true,
		Authentication:       false,
		CapabilityDelegation: false,
		CapabilityInvocation: true,
		KeyAgreement:         false,
		SelfControl:          true,
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

// ErrInvalidOptions is returned when the given options have an invalid combination
var ErrInvalidOptions = errors.New("create request has invalid combination of options: SelfControl = true and CapabilityInvocation = false")

// Create creates a Nuts DID Document with a valid DID id based on a freshly generated keypair.
// The key is added to the verificationMethod list and referred to from the Authentication list
func (n Creator) Create(options vdr.DIDCreationOptions) (*did.Document, nutsCrypto.Key, error) {
	var key nutsCrypto.Key
	var err error

	if options.SelfControl && !options.CapabilityInvocation {
		return nil, nil, ErrInvalidOptions
	}

	// First, generate a new keyPair with the correct kid
	if options.SelfControl {
		key, err = n.KeyStore.New(didKIDNamingFunc)
	} else {
		key, err = nutsCrypto.NewEphemeralKey(didKIDNamingFunc)
	}
	if err != nil {
		return nil, nil, err
	}

	keyID, err := did.ParseDID(key.KID())
	if err != nil {
		return nil, nil, err
	}

	// The Document DID will be the keyIDStr without the fragment:
	didID := *keyID
	didID.Fragment = ""

	// create the bare document
	doc := &did.Document{
		Context:    []ssi.URI{did.DIDContextV1URI()},
		ID:         didID,
		Controller: options.Controllers,
	}

	var verificationMethod *did.VerificationMethod
	if options.SelfControl {
		// Add VerificationMethod using generated key
		verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
		if err != nil {
			return nil, nil, err
		}
		if len(options.Controllers) > 0 {
			// also set as controller
			doc.Controller = append(doc.Controller, didID)
		}
	} else {
		// Generate new key for other key capabilities, store the private key
		capKey, err := n.KeyStore.New(didKIDNamingFunc)
		if err != nil {
			return nil, nil, err
		}
		capKeyID, err := did.ParseDID(capKey.KID())
		if err != nil {
			return nil, nil, err
		}
		verificationMethod, err = did.NewVerificationMethod(*capKeyID, ssi.JsonWebKey2020, did.DID{}, capKey.Public())
		if err != nil {
			return nil, nil, err
		}
	}

	// set all methods
	if options.CapabilityDelegation {
		doc.AddCapabilityDelegation(verificationMethod)
	}
	if options.CapabilityInvocation {
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

	// return the doc and the keyCreator that created the private key
	return doc, key, nil
}
