package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/shengdoushi/base58"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"

	"github.com/nuts-foundation/go-did"
)

// NutsDIDMethodName is the DID method name used by Nuts
const NutsDIDMethodName = "nuts"

// NutsDocCreator implements the DocCreator interface and can create Nuts DID Documents.
type NutsDocCreator struct {
	// keyCreator is used for getting a fresh key and use it to generate the Nuts DID
	keyCreator nutsCrypto.KeyCreator
}

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
func (n NutsDocCreator) Create() (*did.Document, error) {
	// First, generate a new keyPair with the correct kid
	key, keyIDStr, err := n.keyCreator.New(didKIDNamingFunc)
	if err != nil {
		return nil, fmt.Errorf("unable to build did: %w", err)
	}

	// The Document DID will be the keyIDStr without the fragment:
	didID, err := did.ParseDID(keyIDStr)
	if err != nil {
		return nil, err
	}
	didID.Fragment = ""

	keyID, err := did.ParseDID(keyIDStr)
	if err != nil {
		return nil, err
	}
	// Build the AuthenticationMethod and add it to the document
	verificationMethod, err := did.NewVerificationMethod(*keyID, did.JsonWebKey2020, did.DID{}, key)
	if err != nil {
		return nil, err
	}
	// Create the Document with itself as the controller
	doc := &did.Document{
		Context:            []did.URI{did.DIDContextV1URI()},
		ID:                 *didID,
		Controller:         []did.DID{*didID},
	}

	doc.AddAuthenticationMethod(verificationMethod)

	return doc, nil
}

