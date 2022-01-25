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
	"encoding/pem"
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
func PrivateKeyToPem(pub crypto.PrivateKey) (string, error) {
	pubASN1, err := x509.MarshalPKCS8PrivateKey(pub)

	if err != nil {
		return "", err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), err
}

// PemToPrivateKey converts a PEM encoded private key to a Signer interface. It supports EC, RSA and PKIX PEM encoded strings
func PemToPrivateKey(bytes []byte) (signer crypto.Signer, err error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		err = ErrWrongPrivateKey
		return
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		signer, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var key interface{}
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		switch key.(type) {
		case *rsa.PrivateKey:
			signer = key.(*rsa.PrivateKey)
		case *ecdsa.PrivateKey:
			signer = key.(*ecdsa.PrivateKey)
		case ed25519.PrivateKey:
			signer = key.(ed25519.PrivateKey)
		}
	}
	return
}
