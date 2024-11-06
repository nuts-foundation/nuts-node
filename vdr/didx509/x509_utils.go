/*
 * Copyright (C) 2024 Nuts community
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

package didx509

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"strings"
)

type HashAlgorithm string

const (

	// HashSha1 represents the SHA-1 hashing algorithm to be used for generating hash values.
	HashSha1 = HashAlgorithm("sha1")

	// HashSha256 represents the SHA-256 hash algorithm constant, used for cryptographic hashing operations.
	HashSha256 = HashAlgorithm("sha256")

	// HashSha384 represents the SHA-384 hash algorithm.
	HashSha384 = HashAlgorithm("sha384")

	// HashSha512 defines the SHA-512 hash algorithm.
	HashSha512 = HashAlgorithm("sha512")
)

var (

	// ErrUnsupportedHashAlgorithm indicates that the provided hash algorithm is not supported by the system.
	ErrUnsupportedHashAlgorithm = fmt.Errorf("unsupported hash algorithm")

	// ErrInvalidHash indicates that the provided hash is invalid or improperly formatted.
	ErrInvalidHash = fmt.Errorf("invalid hash")

	// ErrCertificateNotfound indicates that a certificate could not be found with the given hash.
	ErrCertificateNotfound = fmt.Errorf("cannot locate a find a certificate with the given hash")

	// ErrInvalidPemBlock indicates that a PEM block is invalid or cannot be decoded properly.
	ErrInvalidPemBlock = fmt.Errorf("invalid PEM block")

	// ErrTrailingData indicates that there is trailing data after an X.509 extension, which should not be present.
	ErrTrailingData = errors.New("x509: trailing data after X.509 extension")

	// ErrSanSequenceData indicates an unexpected sequence in the Subject Alternative Name (SAN) extension.
	ErrSanSequenceData = errors.New("unexpected SAN sequence")
)

// OtherName represents a structure for other name in ASN.1
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

// SanType is an alias for pkix.AttributeTypeAndValue
type SanType pkix.AttributeTypeAndValue

// SanTypeName represents the type name for SAN
type SanTypeName string

var (
	// SubjectAlternativeNameType defines the OID for Subject Alternative Name
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	// OtherNameType defines the OID for Other Name
	OtherNameType = asn1.ObjectIdentifier{2, 5, 5, 5}
)

// findOtherNameValues extracts the value of a specified OtherName types from the certificate
func findOtherNameValues(cert *x509.Certificate) ([]string, error) {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(SubjectAlternativeNameType) {
			return findSanValues(extension)
		}
	}
	return make([]string, 0), nil
}

// findSanValues extracts the SAN values from a given pkix.Extension, returning the resulting values or an error.
func findSanValues(extension pkix.Extension) ([]string, error) {
	var values []string
	err := forEachSan(extension.Value, func(v *asn1.RawValue) error {
		if v.Class == asn1.ClassContextSpecific && v.Tag == 0 {
			var other OtherName
			_, err := asn1.UnmarshalWithParams(v.FullBytes, &other, "tag:0")
			if err != nil {
				return err
			}
			if other.TypeID.Equal(OtherNameType) {
				var value string
				_, err = asn1.Unmarshal(other.Value.Bytes, &value)
				if err != nil {
					return err
				}
				values = append(values, value)
			}
		}
		return nil

	})
	if err != nil {
		return make([]string, 0), err
	}
	return values, err
}

// forEachSan processes each SAN extension in the certificate
func forEachSan(extension []byte, callback func(data *asn1.RawValue) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return ErrTrailingData
	}

	if !isSANSequence(seq) {
		return ErrSanSequenceData
	}

	return processSANSequence(seq.Bytes, callback)
}

// isSANSequence checks if the provided ASN.1 value is a SAN sequence
func isSANSequence(seq asn1.RawValue) bool {
	return seq.IsCompound && seq.Tag == 16 && seq.Class == 0
}

// processSANSequence processes the SAN sequence and invokes the callback on each element
func processSANSequence(rest []byte, callback func(data *asn1.RawValue) error) error {
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error

		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(&v); err != nil {
			return err
		}
	}
	return nil
}

// parseChain extracts the certificate chain from the provided metadata
func parseChain(headerChain *cert.Chain) ([]*x509.Certificate, error) {
	if headerChain == nil {
		return nil, nil
	}
	chain := make([]*x509.Certificate, headerChain.Len())
	for i := range headerChain.Len() {
		certBytes, has := headerChain.Get(i)
		if has {
			pemBlock, _ := pem.Decode(certBytes)
			if pemBlock == nil {
				return nil, ErrInvalidPemBlock
			}
			if pemBlock.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid PEM block type: %s", pemBlock.Type)
			}
			certificate, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, err
			}
			chain[i] = certificate
		}
	}
	return chain, nil
}

// findCertificateByHash searches for a certificate in the provided chain using the given base64url-encoded hash and algorithm.
// If a matching certificate is found, it returns the certificate; otherwise, it returns an error.
func findCertificateByHash(chain []*x509.Certificate, targetHashString string, alg HashAlgorithm) (*x509.Certificate, error) {
	targetHash, err := base64.RawURLEncoding.DecodeString(targetHashString)
	if err != nil {
		return nil, ErrInvalidHash
	}

	for _, c := range chain {
		certHash, err := hash(c.Raw, alg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(targetHash, certHash) {
			return c, nil
		}
	}

	return nil, ErrCertificateNotfound
}

// hash computes and returns the hash of the given data using the specified algorithm.
// Supported algorithms are: "sha1", "sha256", "sha384", "sha512".
// Returns the computed hash as a byte slice and an error if the algorithm is unsupported.
// The error is nil if the hash is computed successfully.
func hash(data []byte, alg HashAlgorithm) ([]byte, error) {
	alg = HashAlgorithm(strings.ToLower(string(alg)))
	switch alg {
	case HashSha1:
		sum := sha1.Sum(data)
		return sum[:], nil
	case HashSha256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case HashSha384:
		sum := sha512.Sum384(data)
		return sum[:], nil
	case HashSha512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	return nil, ErrUnsupportedHashAlgorithm
}
