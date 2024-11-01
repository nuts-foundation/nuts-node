package didx509

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// BuildCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildCertChain(identifier string) (chainCerts [4]*x509.Certificate, chain *cert.Chain, rootCertificate *x509.Certificate, signingKey *rsa.PrivateKey, signingCert *x509.Certificate, err error) {
	chainCerts = [4]*x509.Certificate{}
	chain = &cert.Chain{}
	rootKey, rootCert, rootPem, err := buildRootCert()
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}
	chainCerts[0] = rootCert
	err = chain.Add(rootPem)
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}

	intermediateL1Key, intermediateL1Cert, intermediateL1Pem, err := buildIntermediateCert(err, rootCert, rootKey)
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}
	chainCerts[1] = intermediateL1Cert
	err = chain.Add(intermediateL1Pem)
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}

	intermediateL2Key, intermediateL2Cert, intermediateL2Pem, err := buildIntermediateCert(err, intermediateL1Cert, intermediateL1Key)
	chainCerts[2] = intermediateL2Cert
	err = chain.Add(intermediateL2Pem)
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}

	signingKey, signingCert, signingPEM, err := buildSigningCert(identifier, intermediateL2Cert, intermediateL2Key, "32121323")
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}
	chainCerts[3] = signingCert
	err = chain.Add(signingPEM)
	if err != nil {
		return chainCerts, nil, nil, nil, nil, err
	}
	return chainCerts, chain, rootCert, signingKey, signingCert, nil
}

func buildSigningCert(identifier string, intermediateL2Cert *x509.Certificate, intermediateL2Key *rsa.PrivateKey, serialNumber string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	signingTmpl, err := SigningCertTemplate(nil, identifier)
	if err != nil {
		return nil, nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = serialNumber
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, err
	}
	return signingKey, signingCert, signingPEM, err
}

func buildIntermediateCert(err error, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, parentCert, &intermediateL1Key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return intermediateL1Key, intermediateL1Cert, intermediateL1Pem, nil
}

func buildRootCert() (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return rootKey, rootCert, rootPem, nil
}

// CertTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func CertTemplate(serialNumber *big.Int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"JaegerTracing"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		BasicConstraintsValid: true,
	}
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return &tmpl, nil
}

// SigningCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func SigningCertTemplate(serialNumber *big.Int, identifier string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}

	tmpl := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"NUTS Foundation"},
			CommonName:         "www.example.com",
			Country:            []string{"NL"},
			Locality:           []string{"Amsterdam", "The Hague"},
			OrganizationalUnit: []string{"The A-Team"},
			StreetAddress:      []string{"Amsterdamseweg 100"},
			PostalCode:         []string{"1011 NL"},
			Province:           []string{"Noord-Holland"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 30), // valid for a month
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	// Either the ExtraExtensions SubjectAlternativeNameType is set, or the Subject Alternate Name values are set,
	// both don't mix
	if identifier != "" {
		err := setSanAlternativeName(&tmpl, identifier)
		if err != nil {
			return nil, err
		}
	} else {
		tmpl.DNSNames = []string{"www.example.com", "example.com"}
		tmpl.EmailAddresses = []string{"info@example.com", "no-reply@example.org"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("192.1.2.3"), net.ParseIP("192.1.2.4")}
	}
	return &tmpl, nil
}

func setSanAlternativeName(tmpl *x509.Certificate, identifier string) error {
	raw, err := toRawValue(identifier, "ia5")
	if err != nil {
		return err
	}
	otherName := OtherName{
		TypeID: OtherNameType,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      raw.FullBytes,
		},
	}

	raw, err = toRawValue(otherName, "tag:0")
	if err != nil {
		return err
	}
	var list []asn1.RawValue
	list = append(list, *raw)
	marshal, err := asn1.Marshal(list)
	if err != nil {
		return err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:       SubjectAlternativeNameType,
		Critical: false,
		Value:    marshal,
	})
	return nil
}

// toRawValue marshals an ASN.1 identifier with a given tag, then unmarshals it into a RawValue structure.
func toRawValue(identifier any, tag string) (*asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(identifier, tag)
	if err != nil {
		return nil, err
	}
	var val asn1.RawValue
	_, err = asn1.Unmarshal(b, &val)
	if err != nil {
		return nil, err
	}
	return &val, nil
}

// CreateCert generates a new x509 certificate using the provided template and parent certificates, public and private keys.
// It returns the generated certificate, its PEM-encoded version, and any error encountered during the process.
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, nil, err
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return cert, certPEM, err
}

func TestFindOtherNameValue(t *testing.T) {
	t.Parallel()
	key, certificate, _, err := buildRootCert()
	_, signingCert, _, err := buildSigningCert("123", certificate, key, "4567")
	if err != nil {
		t.Fatalf("failed to build root certificate: %v", err)
	}

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
			name:    "with extensions",
			cert:    signingCert,
			want:    "123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, err := findOtherNameValue(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("findOtherNameValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.want {
				t.Errorf("findOtherNameValue() = %v, want %v", gotName, tt.want)
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
	chainCerts, _, _, _, _, err := BuildCertChain("123")
	if err != nil {
		t.Error(err)
	}
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
	certs, chain, _, _, _, _ := BuildCertChain("123")

	invalidPEM := `-----BEGIN CERTIFICATE-----
Y29ycnVwdCBjZXJ0aWZpY2F0ZQo=
-----END CERTIFICATE-----`
	emptyTypePEM := `-----BEGIN CIPHER TEXT-----
MIIEDTCCAvegAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADA/
-----END CIPHER TEXT-----`
	invalidBase64PEM := `-----BEGIN CERTIFICATE-----
Hello, world!
-----END CERTIFICATE-----`
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
			chain:     chain,
			want:      certs[:], // not critical for testing
			wantError: nil,
		}, {
			name:      "invalid PEM",
			chain:     newChain([][]byte{[]byte(invalidPEM)}),
			want:      nil,
			wantError: errors.New("x509: malformed certificate"),
		}, {
			name:      "PEM with empty type",
			chain:     newChain([][]byte{[]byte(emptyTypePEM)}),
			want:      nil,
			wantError: fmt.Errorf("invalid PEM block type: %s", "CIPHER TEXT"),
		}, {
			name:      "invalid base64 in PEM",
			chain:     newChain([][]byte{[]byte(invalidBase64PEM)}),
			want:      nil,
			wantError: ErrInvalidPemBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, foundErr := parseChain(tt.chain)
			if !errors.Is(foundErr, tt.wantError) {
				if foundErr.Error() != tt.wantError.Error() {
					t.Errorf("parseChain() error = %v, want: %v", foundErr, tt.wantError)
				}
				return
			}
			if len(chain) != len(tt.want) {
				t.Errorf("parseChain() error, wrong number of parsed certs: %d, want: %d", len(chain), len(tt.want))
				return
			}
		})
	}
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
	callback := func(data []byte) error {
		if !bytes.Equal(data, testRawValue.FullBytes) {
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
	callback := func(data []byte) error {
		if !bytes.Equal(data, testEncapsulatedValue.FullBytes) {
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
			val, foundErr := findSanValue(pkix.Extension{
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
							t.Errorf("findSanValue() error = %v, want: %v", foundErr, tt.wantError)
							return
						}
					}
				}
			}

			if val != tt.expectedValue {
				t.Errorf("findSanValue() = %v, want: %v", val, tt.expectedValue)
			}

		})
	}
}
