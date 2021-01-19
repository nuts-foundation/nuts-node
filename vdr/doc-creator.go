package vdr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/shengdoushi/base58"

	"github.com/nuts-foundation/go-did"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

const NutsDIDMethodName = "nuts"

type DocCreator struct {
	keyCreator nutsCrypto.KeyCreator
}

func didKidNamingFunc(pKey crypto.PublicKey) (string, error) {
	ecPKey := pKey.(*ecdsa.PublicKey)
	pkBytes := elliptic.Marshal(ecPKey.Curve, ecPKey.X, ecPKey.Y)
	pkHash := sha256.Sum256(pkBytes)

	jwKey, err := jwk.New(pKey)
	if err != nil {
		return "", err
	}
	err = jwk.AssignKeyID(jwKey)
	if err != nil {
		return "", err
	}

	idString := base58.Encode(pkHash[:], base58.BitcoinAlphabet)
	kid := &did.DID{}
	kid.ID = idString
	kid.Method = NutsDIDMethodName
	kid.Fragment = jwKey.KeyID()

	return kid.String(), nil
}

//BuildDID
func (n DocCreator) Create() (*did.Document, error) {
	key, kidIDStr, err := n.keyCreator.New(didKidNamingFunc)
	if err != nil {
		return nil, fmt.Errorf("unable to build did: %w", err)
	}
	didID, err := did.ParseDID(kidIDStr)
	didID.Fragment = ""

	publicKeyJWK, err := jwk.New(key)
	if err != nil {
		return nil, err
	}
	err = publicKeyJWK.Set(jwk.KeyIDKey, kidIDStr)
	if err != nil {
		return nil, err
	}

	jwk.AssignKeyID(publicKeyJWK)
	if err != nil {
		return nil, err
	}

	verificationMethod, err := jwkToVerificationMethod(publicKeyJWK)

	doc := &did.Document{
		Context:            []did.URI{did.DIDContextV1URI()},
		ID:                 *didID,
		VerificationMethod: []did.VerificationMethod{*verificationMethod},
		Authentication:     []did.VerificationRelationship{{VerificationMethod: verificationMethod}},
	}
	return doc, nil
}

func jwkToVerificationMethod(key jwk.Key) (*did.VerificationMethod, error) {
	publicKeyAsJWKAsMap, err := key.AsMap(context.Background())
	if err != nil {
		return nil, err
	}
	kid, err := url.Parse(key.KeyID())
	if err != nil {
		return nil, err
	}
	return &did.VerificationMethod{
		ID:           did.URI{URL: *kid},
		Type:         did.JsonWebKey2020,
		PublicKeyJwk: publicKeyAsJWKAsMap,
	}, nil
}
