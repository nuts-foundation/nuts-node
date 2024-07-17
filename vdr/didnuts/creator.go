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

package didnuts

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// MethodName is the DID method name used by Nuts
const MethodName = "nuts"

// NutsDIDContextV1 contains the Nuts specific JSON-LD context for a DID Document
const NutsDIDContextV1 = "https://nuts.nl/did/v1"

// NutsDIDContextV1URI returns NutsDIDContextV1 as a URI
func NutsDIDContextV1URI() ssi.URI {
	return ssi.MustParseURI(NutsDIDContextV1)
}

// CreateDocument creates an empty DID document with baseline properties set.
func CreateDocument() did.Document {
	return did.Document{
		Context: []interface{}{NutsDIDContextV1URI(), jsonld.JWS2020ContextV1URI(), did.DIDContextV1URI()},
	}
}

// Creator implements the DocCreator interface and can create Nuts DID Documents.
type Creator struct {
	// KeyStore is used for getting a fresh key and use it to generate the Nuts DID
	KeyStore nutsCrypto.KeyCreator

	// NetworkClient is used for publishing the newly created DID Document
	NetworkClient network.Transactions

	// DIDResolver is used for resolving the controllers of the newly created DID Document
	DIDResolver resolver.DIDResolver
}

// DefaultCreationOptions returns the default CreationOptions when creating DID Documents.
func DefaultCreationOptions() management.CreationOptions {
	return management.Create(MethodName).
		With(KeyFlag(DefaultKeyFlags()))
}

// DefaultKeyFlags returns the default DIDKeyFlags when creating did:nuts DIDs.
func DefaultKeyFlags() management.DIDKeyFlags {
	return management.AssertionMethodUsage | management.CapabilityInvocationUsage | management.KeyAgreementUsage
}

type keyFlagCreationOption management.DIDKeyFlags

// KeyFlag specifies for what purposes the generated key can be used
func KeyFlag(flags management.DIDKeyFlags) management.CreationOption {
	return keyFlagCreationOption(flags)
}

// DIDKIDNamingFunc is a function used to name a key used in newly generated DID Documents.
func DIDKIDNamingFunc(pKey crypto.PublicKey) (string, error) {
	return getKIDName(pKey, nutsCrypto.Thumbprint)
}

// didSubKIDNamingFunc returns a KIDNamingFunc that can be used as param in the KeyStore.New function.
// It wraps the KIDNamingFunc with the context of the DID of the document.
// It returns a keyID in the form of the documents DID with the new keys thumbprint as fragment.
// E.g. for a assertionMethod key that differs from the key the DID document was created with.
func didSubKIDNamingFunc(owningDID did.DID) nutsCrypto.KIDNamingFunc {
	return func(pKey crypto.PublicKey) (string, error) {
		return getKIDName(pKey, func(_ jwk.Key) (string, error) {
			return owningDID.ID, nil
		})
	}
}

func getKIDName(pKey crypto.PublicKey, idFunc func(key jwk.Key) (string, error)) (string, error) {
	// according to RFC006:
	// --------------------

	// generate idString
	jwKey, err := jwk.FromRaw(pKey)
	if err != nil {
		return "", fmt.Errorf("could not generate kid: %w", err)
	}

	idString, err := idFunc(jwKey)
	if err != nil {
		return "", err
	}

	// generate kid fragment
	err = jwk.AssignKeyID(jwKey)
	if err != nil {
		return "", err
	}

	// assemble
	kid := &did.DIDURL{}
	kid.Method = MethodName
	kid.ID = idString
	kid.Fragment = jwKey.KeyID()

	return kid.String(), nil
}

// ErrInvalidOptions is returned when the given options have an invalid combination
var ErrInvalidOptions = errors.New("create request has invalid combination of options: SelfControl = true and CapabilityInvocation = false")

// Create creates a Nuts DID Document with a valid DID id based on a freshly generated keypair.
// The key is added to the verificationMethod list and referred to from the Authentication list
// It also publishes the DID Document to the network.
func (n Creator) Create(ctx context.Context, options management.CreationOptions) (*did.Document, nutsCrypto.Key, error) {
	keyFlags, err := parseOptions(options)
	if err != nil {
		return nil, nil, err
	}

	if !keyFlags.Is(management.CapabilityInvocationUsage) {
		return nil, nil, ErrInvalidOptions
	}

	doc, key, err := n.create(ctx, keyFlags)
	if err != nil {
		return nil, nil, err
	}
	if err := n.publish(ctx, *doc, key); err != nil {
		return nil, nil, err
	}

	// return the doc and the keyCreator that created the private key
	return doc, key, nil
}

func parseOptions(options management.CreationOptions) (keyFlags management.DIDKeyFlags, err error) {
	for _, opt := range options.All() {
		switch o := opt.(type) {
		case keyFlagCreationOption:
			keyFlags = management.DIDKeyFlags(o)
		default:
			return 0, fmt.Errorf("unknown option: %T", opt)
		}
	}
	return
}

func (n Creator) create(ctx context.Context, flags management.DIDKeyFlags) (*did.Document, nutsCrypto.Key, error) {
	// First, generate a new keyPair with the correct kid
	// Currently, always keep the key in the keystore. This allows us to change the transaction format and regenerate transactions at a later moment.
	// Relevant issue:
	// https://github.com/nuts-foundation/nuts-node/issues/1947
	key, err := n.KeyStore.New(ctx, DIDKIDNamingFunc)
	// } else {
	// 	key, err = nutsCrypto.NewEphemeralKey(didKIDNamingFunc)
	// }
	if err != nil {
		return nil, nil, err
	}

	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, nil, err
	}

	// Create the bare document. The Document DID will be the keyIDStr without the fragment.
	didID, _ := resolver.GetDIDFromURL(key.KID())
	doc := CreateDocument()
	doc.ID = didID

	var verificationMethod *did.VerificationMethod

	// Add VerificationMethod using generated key
	verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
	if err != nil {
		return nil, nil, err
	}

	applyKeyUsage(&doc, verificationMethod, flags)
	return &doc, key, nil
}

func (n Creator) publish(ctx context.Context, doc did.Document, key nutsCrypto.Key) error {
	payload, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	// extract the transaction refs from the controller metadata
	refs := make([]hash.SHA256Hash, 0)

	tx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
	_, err = n.NetworkClient.CreateTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("could not store DID document in network: %w", err)
	}
	return nil
}

// applyKeyUsage checks intendedKeyUsage and adds the given verificationMethod to every relationship specified as key usage.
func applyKeyUsage(document *did.Document, keyToAdd *did.VerificationMethod, intendedKeyUsage management.DIDKeyFlags) {
	if intendedKeyUsage.Is(management.CapabilityDelegationUsage) {
		document.AddCapabilityDelegation(keyToAdd)
	}
	if intendedKeyUsage.Is(management.CapabilityInvocationUsage) {
		document.AddCapabilityInvocation(keyToAdd)
	}
	if intendedKeyUsage.Is(management.AuthenticationUsage) {
		document.AddAuthenticationMethod(keyToAdd)
	}
	if intendedKeyUsage.Is(management.AssertionMethodUsage) {
		document.AddAssertionMethod(keyToAdd)
	}
	if intendedKeyUsage.Is(management.KeyAgreementUsage) {
		document.AddKeyAgreement(keyToAdd)
	}
}
