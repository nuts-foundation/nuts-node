package util

import (
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// oidNamedCurveP256k1 is the ASN.1 object identifier of the secp256k1 curve.
// See http://oidref.com/1.3.132.0.10
var oidNamedCurveP256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// oidPublicKeyECDSA is the ASN.1 object identifier of a ECDSA public key.
// See https://oidref.com/1.2.840.10045.2.1
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

type asn1PKCS8Container struct {
	Version int
	Algo    pkix.AlgorithmIdentifier
	Data    []byte
}

type asn1ECPrivateKey struct {
	Version int
	Data    []byte
	Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
}

// marshalSecp256k1PKCS8 marshals a secp256k1 private key into ASN.1, PKCS #8 format.
// It's inspired by crypto/x509/pkcs8.go
func marshalSecp256k1PKCS8(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	oidBytes, err := asn1.Marshal(oidNamedCurveP256k1)
	if err != nil {
		// Would be weird
		return nil, err
	}
	if !secp256k1.S256().IsOnCurve(privateKey.X, privateKey.Y) {
		return nil, errors.New("invalid secp256k1 public key")
	}
	pkData, err := asn1.Marshal(asn1ECPrivateKey{
		Version: 1,
		Data:    privateKey.D.Bytes(),
		Curve:   oidNamedCurveP256k1,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1PKCS8Container{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		},
		Data: pkData,
	})
}
