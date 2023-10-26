/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PemToPublicKey converts a PEM encoded public key to a crypto.PublicKey
func PemToPublicKey(pub []byte) (crypto.PublicKey, error) {

	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, ErrWrongPublicKey
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, ErrWrongPublicKey
	}
}

// PublicKeyToPem converts an public key to PEM encoding
func PublicKeyToPem(pub crypto.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)

	if err != nil {
		return "", err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), err
}

// PrivateKeyToPem converts an public key to PEM encoding
func PrivateKeyToPem(privateKey crypto.PrivateKey) (string, error) {
	var pubASN1 []byte
	var err error

	if pk, ok := privateKey.(*ecdsa.PrivateKey); ok && pk.Curve == secp256k1.S256() {
		privateKey = secp256k1.PrivKeyFromBytes(pk.D.Bytes())
	}

	var pemType string
	switch pk := privateKey.(type) {
	case *secp256k1.PrivateKey:
		pubASN1, err = marshalSecp256k1(pk)
		pemType = "EC PRIVATE KEY"
	default:
		pubASN1, err = x509.MarshalPKCS8PrivateKey(privateKey)
		pemType = "PRIVATE KEY"
	}
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: pubASN1,
	})

	return string(pubBytes), err
}

// PemToPrivateKey converts a PEM encoded private key to a Signer interface. It supports EC, RSA (PKCS1) and PKCS8 PEM encoded strings
func PemToPrivateKey(bytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrWrongPrivateKey
	}
	var err error
	var result crypto.Signer
	switch block.Type {
	case "RSA PRIVATE KEY":
		result, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		result, err = parseECPrivateKey(block)
	case "PRIVATE KEY":
		var key interface{}
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			if err.Error() == "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)" {
				result, err = parseECPrivateKey(block)
			}
		} else {
			switch k := key.(type) {
			case *rsa.PrivateKey:
				result = k
			case *ecdsa.PrivateKey:
				result = k
			case ed25519.PrivateKey:
				result = k
			}
		}
	}
	if result == nil {
		return nil, errors.Join(ErrWrongPrivateKey, err)
	}
	return result, nil
}

// parseECPrivateKey parses EC private keys, trying Golang's x509 package first,
// and then trying other, by default unsupported keys (secp256k1
func parseECPrivateKey(block *pem.Block) (crypto.Signer, error) {
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		if err.Error() == "x509: unknown elliptic curve" {
			// Might be secp256k1
			return unmarshalSecp256k1(block.Bytes)
		}
		return nil, err
	}
	return pk, nil
}

// unmarshalSecp256k1 unmarshals into a secp256k1 private key, provided in ASN.1 format, according to section 4.3.6 of ANSI X9.62
func unmarshalSecp256k1(data []byte) (crypto.Signer, error) {
	var privateKeyDER asn1ECPrivateKey
	_, err := asn1.Unmarshal(data, &privateKeyDER)
	if err != nil {
		return nil, err
	}
	if !privateKeyDER.Curve.Equal(oidNamedCurveP256k1) {
		return nil, errors.New("unknown elliptic curve")
	}
	return secp256k1.PrivKeyFromBytes(privateKeyDER.Data).ToECDSA(), nil
}

// oidNamedCurveP256k1 is the ASN.1 object identifier of the secp256k1 curve.
// See http://oidref.com/1.3.132.0.10
var oidNamedCurveP256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type asn1ECPrivateKey struct {
	Version int
	Data    []byte
	Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
}

// marshalSecp256k1 marshals a secp256k1 private key into ASN.1 format, according to section 4.3.6 of ANSI X9.62
func marshalSecp256k1(privateKey *secp256k1.PrivateKey) ([]byte, error) {
	pubKey := privateKey.PubKey()
	if !secp256k1.S256().IsOnCurve(pubKey.X(), pubKey.Y()) {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return asn1.Marshal(asn1ECPrivateKey{
		Version: 1,
		Data:    privateKey.Serialize(),
		Curve:   oidNamedCurveP256k1,
	})
}
