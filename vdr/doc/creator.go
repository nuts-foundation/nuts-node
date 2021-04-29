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
	"fmt"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/shengdoushi/base58"

	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// NutsDIDMethodName is the DID method name used by Nuts
const NutsDIDMethodName = "nuts"

// Creator implements the DocCreator interface and can create Nuts DID Documents.
type Creator struct {
	// KeyCreator is used for getting a fresh key and use it to generate the Nuts DID
	KeyCreator nutsCrypto.KeyCreator
}

// didKIDNamingFunc is a function used to name a key used in newly generated DID Documents
func didKIDNamingFunc(pKey crypto.PublicKey) (string, error) {
	// according to RFC006:
	// --------------------

	// generate idString
	jwKey, err := jwk.New(pKey)
	if err != nil {
		return "", fmt.Errorf("could not generate kid: invalid key type")
	}

	pkHash, err := jwKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	idString := base58.Encode(pkHash[:], base58.BitcoinAlphabet)

	// generate kid fragment
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
func (n Creator) Create() (*did.Document, error) {
	// First, generate a new keyPair with the correct kid
	key, keyIDStr, err := n.KeyCreator.New(didKIDNamingFunc)
	if err != nil {
		return nil, fmt.Errorf("unable to build did: %w", err)
	}

	keyID, err := did.ParseDID(keyIDStr)
	if err != nil {
		return nil, err
	}

	// The Document DID will be the keyIDStr without the fragment:
	didID := *keyID
	didID.Fragment = ""

	// Build the AuthenticationMethod and add it to the document
	verificationMethod, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key)
	if err != nil {
		return nil, err
	}

	doc := &did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      didID,
	}

	doc.AddCapabilityInvocation(verificationMethod)

	return doc, nil
}
