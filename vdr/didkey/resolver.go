package didkey

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/multiformats/go-multicodec"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/shengdoushi/base58"
)

// MethodName is the name of this DID method.
const MethodName = "key"

var _ resolver.DIDResolver = &Resolver{}

var errInvalidPublicKeyLength = errors.New("invalid did:key: invalid public key length")

type Resolver struct {
}

func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
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
	keyLength := reader.Len()
	switch multicodec.Code(keyType) {
	case multicodec.Secp256k1Pub:
		if keyLength != 33 {
			return nil, nil, errInvalidPublicKeyLength
		}
		return nil, nil, errors.New("TODO: support secp256k1 public key")
	case multicodec.X25519Pub:
		if keyLength != 32 {
			return nil, nil, errInvalidPublicKeyLength
		}
		key = x25519.PublicKey(mcBytes[1:])
	case multicodec.Ed25519Pub:
		if keyLength != 32 {
			return nil, nil, errInvalidPublicKeyLength
		}
		key = ed25519.PublicKey(mcBytes[1:])
	case multicodec.P256Pub:
		if keyLength != 33 {
			return nil, nil, errInvalidPublicKeyLength
		}
		return nil, nil, errors.New("TODO: find out P256 pub key encoding")
	case multicodec.P384Pub:
		if keyLength != 49 {
			return nil, nil, errInvalidPublicKeyLength
		}
		return nil, nil, errors.New("TODO: find out P384 pub key encoding")
	case multicodec.P521Pub:
		return nil, nil, errors.New("TODO: find out P521 pub key encoding")
	case multicodec.RsaPub:
		key, err = x509.ParsePKCS1PublicKey(mcBytes[1:])
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
