package didkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/multiformats/go-multicodec"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/shengdoushi/base58"
	"io"
)

// MethodName is the name of this DID method.
const MethodName = "key"

var _ resolver.DIDResolver = &Resolver{}

var errInvalidPublicKeyLength = errors.New("invalid did:key: invalid public key length")

// NewResolver creates a new Resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

type Resolver struct {
}

func (r Resolver) Resolve(id did.DID, _ *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	if id.Method != MethodName {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}
	encodedKey := id.ID
	if len(encodedKey) == 0 || encodedKey[0] != 'z' {
		return nil, nil, errors.New("did:key does not start with 'z'")
	}
	mcBytes, err := base58.Decode(encodedKey[1:], base58.BitcoinAlphabet)
	if err != nil {
		return nil, nil, fmt.Errorf("did:key: invalid base58btc: %w", err)
	}
	reader := bytes.NewReader(mcBytes)
	keyType, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("did:key: invalid base58btc: %w", err)
	}
	// See https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm
	var key crypto.PublicKey
	mcBytes, _ = io.ReadAll(reader)
	keyLength := len(mcBytes)

	switch multicodec.Code(keyType) {
	case multicodec.Secp256k1Pub:
		// lestrrat/jwk.New() is missing support for secp256k1
		return nil, nil, errors.New("did:key: secp256k1 public keys are not supported")
	case multicodec.Ed25519Pub:
		if keyLength != 32 {
			return nil, nil, errInvalidPublicKeyLength
		}
		key = ed25519.PublicKey(mcBytes)
	case multicodec.P256Pub:
		if key, err = unmarshalEC(elliptic.P256(), 33, mcBytes); err != nil {
			return nil, nil, err
		}
	case multicodec.P384Pub:
		if key, err = unmarshalEC(elliptic.P384(), 33, mcBytes); err != nil {
			return nil, nil, err
		}
	case multicodec.P521Pub:
		if key, err = unmarshalEC(elliptic.P521(), 33, mcBytes); err != nil {
			return nil, nil, err
		}
	case multicodec.RsaPub:
		key, err = x509.ParsePKCS1PublicKey(mcBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("did:key: invalid PKCS#1 encoded RSA public key: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("did:key: unsupported public key type: %d", keyType)
	}

	document := did.Document{
		Context: []ssi.URI{
			ssi.MustParseURI("https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"),
			did.DIDContextV1URI(),
		},
		ID: id,
	}
	keyID := id
	keyID.Fragment = id.ID
	vm, err := did.NewVerificationMethod(keyID, ssi.JsonWebKey2020, id, key)
	if err != nil {
		return nil, nil, err
	}
	document.AddAssertionMethod(vm)
	document.AddAuthenticationMethod(vm)
	document.AddKeyAgreement(vm)
	document.AddCapabilityDelegation(vm)
	document.AddCapabilityInvocation(vm)
	return &document, &resolver.DocumentMetadata{}, nil
}

func unmarshalEC(curve elliptic.Curve, expectedLen int, pubKeyBytes []byte) (ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != expectedLen {
		return ecdsa.PublicKey{}, errInvalidPublicKeyLength
	}
	x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
	return ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
