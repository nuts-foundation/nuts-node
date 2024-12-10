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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/stretchr/testify/require"
	"slices"
	"strings"
	"testing"
)

func TestFindOtherNameValue(t *testing.T) {
	t.Parallel()
	key, certificate, err := pki.BuildRootCert()
	require.NoError(t, err)
	_, signingCert, err := pki.BuildSigningCert([]string{"123", "321"}, certificate, key, "4567")
	require.NoError(t, err)

	tests := []struct {
		name    string
		cert    *x509.Certificate
		want    string
		wantErr bool
	}{
		{
			name:    "no extensions",
			cert:    certificate,
			want:    "",
			wantErr: false,
		},
		{
			name:    "with extensions first",
			cert:    signingCert,
			want:    "123",
			wantErr: false,
		},
		{
			name:    "with extensions second",
			cert:    signingCert,
			want:    "321",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, err := findOtherNameValues(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("findOtherNameValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != "" && !slices.Contains(gotName, tt.want) {
				t.Errorf("findOtherNameValues() = %v, want %v", gotName, tt.want)
			}
		})
	}
}

func TestFindCertificateByHash(t *testing.T) {
	hashToString := func(data []byte, alg HashAlgorithm) string {
		h, err := hash(data, alg)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(h)
	}
	chainCerts, _, err := pki.BuildCertChain([]string{"123"}, "")
	require.NoError(t, err)
	t.Parallel()
	type testCase struct {
		name      string
		chain     []*x509.Certificate
		hash      string
		alg       HashAlgorithm
		wantCert  *x509.Certificate
		wantError error
	}
	cases := []testCase{
		{
			name:      "invalid SHA256 hash",
			chain:     chainCerts[:],
			hash:      "not_a_valid_base64_hash",
			alg:       HashSha256,
			wantCert:  nil,
			wantError: ErrCertificateNotfound,
		}, {
			name:      "invalid SHA256 base64 hash",
			chain:     chainCerts[:],
			hash:      "=====",
			alg:       HashSha256,
			wantCert:  nil,
			wantError: ErrInvalidHash,
		}, {
			name:      "empty chain",
			chain:     []*x509.Certificate{},
			hash:      "L77NA_nbst_9b0yg5ciFcJGhpufJ9nDgVCY9vNS8sepR",
			alg:       HashSha256,
			wantCert:  nil,
			wantError: ErrCertificateNotfound,
		},
		{
			name:      "wrong SHA256 hash",
			chain:     chainCerts[:],
			hash:      hashToString(chainCerts[0].Raw, HashSha1),
			alg:       HashSha256,
			wantCert:  nil,
			wantError: ErrCertificateNotfound,
		},
		{
			name:      "valid SHA512 hash with different algorithm",
			chain:     chainCerts[:],
			hash:      hashToString(chainCerts[0].Raw, HashSha256),
			alg:       HashSha1,
			wantCert:  nil,
			wantError: ErrCertificateNotfound,
		},
	}

	for _, alg := range []HashAlgorithm{HashSha1, HashSha256, HashSha512, HashSha384} {
		cases = append(cases, testCase{
			name:     fmt.Sprintf("valid %s hash", alg),
			chain:    chainCerts[:],
			hash:     hashToString(chainCerts[0].Raw, alg),
			alg:      alg,
			wantCert: chainCerts[0],
		})
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			foundCert, foundErr := findCertificateByHash(tt.chain, tt.hash, tt.alg)
			if !errors.Is(foundErr, tt.wantError) {
				t.Errorf("findCertificateByHash() error = %v, wantErr %v", foundErr, tt.wantError)
				return
			}
			if foundCert != nil && tt.wantCert == nil {
				t.Errorf("findCertificateByHash() = %v, want %v", foundCert, "nil")
				return
			}
			if tt.wantCert != nil {
				if foundCert == nil {
					t.Errorf("findCertificateByHash() = %v, want %v", "nil", tt.wantCert)
					return
				}
				if !bytes.Equal(foundCert.Raw, tt.wantCert.Raw) {
					t.Errorf("findCertificateByHash() = %v, want %v", foundCert, tt.wantCert)
					return
				}
			}
		})
	}
}

// TestParseChain tests the parseChain function with cases that contain valid and invalid PEM encoded certificates.
func TestParseChain(t *testing.T) {
	newChain := func(pems [][]byte) *cert.Chain {
		chain := cert.Chain{}
		for _, pemCert := range pems {
			err := chain.Add(pemCert)
			if err != nil {
				panic(err)
			}
		}
		return &chain
	}
	certs, _, _ := pki.BuildCertChain([]string{"123"}, "")

	invalidCert := `Y29ycnVwdCBjZXJ0aWZpY2F0ZQo=`
	invalidBase64 := `Hello, world!`
	tests := []struct {
		name      string
		chain     *cert.Chain
		want      []*x509.Certificate
		wantError error
	}{
		{
			name:      "null argument",
			chain:     nil,
			want:      nil,
			wantError: nil,
		}, {
			name:      "valid certificate",
			chain:     pki.CertsToChain(certs),
			want:      certs[:], // not critical for testing
			wantError: nil,
		}, {
			name:      "invalid cert",
			chain:     newChain([][]byte{[]byte(invalidCert)}),
			want:      nil,
			wantError: errors.New("x509: malformed certificate"),
		}, {
			name:      "invalid base64",
			chain:     newChain([][]byte{[]byte(invalidBase64)}),
			want:      nil,
			wantError: errors.New("illegal base64 data at input byte 5"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, foundErr := parseChain(tt.chain)
			if tt.wantError == nil {
				require.NoError(t, foundErr)
			} else {
				require.EqualError(t, foundErr, tt.wantError.Error())
			}
			if len(chain) != len(tt.want) {
				t.Errorf("parseChain() error, wrong number of parsed certs: %d, want: %d", len(chain), len(tt.want))
				return
			}
		})
	}
}

func leafCertFromCerts(certs []*x509.Certificate) *x509.Certificate {
	return certs[0]
}

func rootCertFromCerts(certs []*x509.Certificate) *x509.Certificate {
	return certs[len(certs)-1]
}

func TestProcessSANSequence(t *testing.T) {
	asn1Marshal := func(data interface{}) []byte {
		marshal, _ := asn1.Marshal(data)
		return marshal
	}
	testValue := asn1Marshal("testValue")
	testRawValue := asn1.RawValue{}
	_, err := asn1.Unmarshal(testValue, &testRawValue)
	if err != nil {
		panic(err)
	}
	wrongValueErr := errors.New("wrong value")
	callback := func(v *asn1.RawValue) error {
		if !bytes.Equal(v.FullBytes, testRawValue.FullBytes) {
			return wrongValueErr
		}
		return nil
	}

	tests := []struct {
		name      string
		rest      []byte
		wantError error
	}{
		{
			name:      "happy case",
			rest:      testValue,
			wantError: nil,
		},
		{
			name:      "empty sequence",
			rest:      []byte{},
			wantError: nil,
		},
		{
			name:      "sequence with wrong data",
			rest:      testValue[2:],
			wantError: errors.New("asn1: syntax error: data truncated"),
		},
		{
			name:      "sequence with wrong value",
			rest:      asn1Marshal("wrongValueErr"),
			wantError: wrongValueErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foundErr := processSANSequence(tt.rest, callback)
			if !errors.Is(foundErr, tt.wantError) {
				if foundErr.Error() != tt.wantError.Error() {
					t.Errorf("processSANSequence() error = %v, want: %v", foundErr, tt.wantError)
				}
				return
			}
		})
	}
}

func TestForEachSan(t *testing.T) {
	asn1Marshal := func(data interface{}) []byte {
		marshal, _ := asn1.Marshal(data)
		return marshal
	}
	testEncapsulated := asn1Marshal("testValue")
	testEncapsulatedValue := asn1.RawValue{}
	_, err := asn1.Unmarshal(testEncapsulated, &testEncapsulatedValue)
	if err != nil {
		panic(err)
	}
	wrongValueErr := errors.New("wrong value")
	callback := func(v *asn1.RawValue) error {
		if !bytes.Equal(v.FullBytes, testEncapsulatedValue.FullBytes) {
			return wrongValueErr
		}
		return nil
	}

	testValue := asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testEncapsulated})

	tests := []struct {
		name      string
		rest      []byte
		wantError error
	}{
		{
			name:      "happy case",
			rest:      testValue,
			wantError: nil,
		},
		{
			name:      "empty sequence",
			rest:      []byte{},
			wantError: errors.New("asn1: syntax error: sequence truncated"),
		},
		{
			name:      "botched sequence",
			rest:      asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testEncapsulated})[2:],
			wantError: errors.New("unexpected SAN sequence"),
		},
		{
			name:      "sequence with wrong value",
			rest:      asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: asn1Marshal("wrongValue")}),
			wantError: wrongValueErr,
		},
		{
			name:      "sequence with wrong  IsCompound",
			rest:      asn1Marshal(asn1.RawValue{IsCompound: false, Tag: 16, Bytes: testEncapsulated}),
			wantError: ErrSanSequenceData,
		},
		{
			name:      "sequence with wrong Class",
			rest:      asn1Marshal(asn1.RawValue{IsCompound: true, Class: 1, Tag: 16, Bytes: testEncapsulated}),
			wantError: ErrSanSequenceData,
		},
		{
			name:      "sequence with wrong Tag",
			rest:      asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 17, Bytes: testEncapsulated}),
			wantError: ErrSanSequenceData,
		},
		{
			name:      "sequence with unexpected tail",
			rest:      append(asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 17, Bytes: testEncapsulated}), asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 17, Bytes: testEncapsulated})...),
			wantError: ErrTrailingData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foundErr := forEachSan(tt.rest, callback)
			if !errors.Is(foundErr, tt.wantError) {
				if tt.wantError == nil {
					t.Errorf("forEachSan() error = %v", foundErr)
				}
				if foundErr == nil {
					t.Errorf("forEachSan() want: %v", tt.wantError)
				}
				if foundErr.Error() != tt.wantError.Error() {
					t.Errorf("forEachSan() error = %v, want: %v", foundErr, tt.wantError)
					return
				}
			}
		})
	}
}

func TestFindSanValue(t *testing.T) {
	asn1MarshalWithParams := func(data interface{}, params string) []byte {
		marshal, _ := asn1.MarshalWithParams(data, params)
		return marshal
	}
	asn1Marshal := func(data interface{}) []byte {
		marshal, _ := asn1.Marshal(data)
		return marshal
	}
	expectedValue := "expectedValue"
	expectedValue2 := "expectedValue2"

	testSanBlock := asn1MarshalWithParams(OtherName{
		TypeID: OtherNameType,
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams(expectedValue, "explicit")},
	}, "tag:0")
	testSanBlock2 := asn1MarshalWithParams(OtherName{
		TypeID: OtherNameType,
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams(expectedValue2, "explicit")},
	}, "tag:0")
	testSanBlockWrongValue := asn1MarshalWithParams(OtherName{
		TypeID: OtherNameType,
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams([]byte{7, 8, 9}, "explicit")},
	}, "tag:0")

	testSanBlockWrongType := asn1MarshalWithParams(OtherName{
		TypeID: asn1.ObjectIdentifier{6, 6, 6, 6},
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams(expectedValue, "explicit")},
	}, "tag:0")
	testSanBlockWrongTag1 := asn1MarshalWithParams(OtherName{
		TypeID: OtherNameType,
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams(expectedValue, "")},
	}, "tag:0")
	testSanBlockWrongTag2 := asn1MarshalWithParams(OtherName{
		TypeID: OtherNameType,
		Value:  asn1.RawValue{FullBytes: asn1MarshalWithParams(expectedValue, "explicit")},
	}, "")

	tests := []struct {
		name           string
		rest           []byte
		wantError      error
		expectAsnError bool
		expectedValue  string
	}{
		{
			name:          "happy case",
			rest:          asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testSanBlock}),
			wantError:     nil,
			expectedValue: expectedValue,
		},
		{
			name:          "happy case double",
			rest:          asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: append(testSanBlock, testSanBlock2...)}),
			wantError:     nil,
			expectedValue: expectedValue2, // Funky, but could happen.
		},
		{
			name:          "wrong type",
			rest:          asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testSanBlockWrongType}),
			wantError:     nil,
			expectedValue: "",
		},
		{
			name:           "wrong value",
			rest:           asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testSanBlockWrongValue}),
			expectAsnError: true,
		},
		{
			name:           "wrong tag 1",
			rest:           asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testSanBlockWrongTag1}),
			expectAsnError: true,
		},
		{
			name:           "wrong tag 2",
			rest:           asn1Marshal(asn1.RawValue{IsCompound: true, Tag: 16, Bytes: testSanBlockWrongTag2}),
			expectAsnError: true,
		},
		{
			name:           "empty sequence",
			rest:           []byte{},
			expectAsnError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, foundErr := findSanValues(pkix.Extension{
				Value: tt.rest,
			})
			if foundErr != nil {
				if tt.expectAsnError {
					if !strings.HasPrefix(foundErr.Error(), "asn1: ") {
						t.Errorf("forEachSan() error = %v", foundErr)
						return
					}
				} else {
					if !errors.Is(foundErr, tt.wantError) {
						if tt.wantError == nil {
							t.Errorf("forEachSan() error = %v", foundErr)
						}
						if foundErr.Error() != tt.wantError.Error() {
							t.Errorf("findSanValues() error = %v, want: %v", foundErr, tt.wantError)
							return
						}
					}
				}
			}

			if tt.expectedValue != "" && !slices.Contains(val, tt.expectedValue) {
				t.Errorf("findSanValues() = %v, want: %v", val, tt.expectedValue)
			}

		})
	}
}
