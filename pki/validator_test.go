/*
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"
)

const (
	testdatapath   = "./test"
	truststore     = testdatapath + "/truststore.pem"
	truststorePKIo = testdatapath + "/truststore_withPKIOverheid.pem"
	pkiOverheidCRL = testdatapath + "/pkioverheid.crl"
	rootCRLurl     = "http://certs.nuts.nl/RootCALatest.crl"
)

// crlPathMap maps the URI path to location on of CRL on disk
var crlPathMap = map[string]string{
	"/RootCALatest.crl":          testdatapath + "/RootCALatest.crl",
	"/IntermediateCAALatest.crl": testdatapath + "/IntermediateCAALatest.crl",
	"/IntermediateCABLatest.crl": "does not exist",
	"/IntermediateCACLatest.crl": testdatapath + "/IntermediateCACLatest.crl",
}

func TestValidator_Start(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	store, err := core.LoadTrustStore(truststorePKIo)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	val, err := newValidatorWithHTTPClient(TestConfig(t), newClient())
	require.NoError(t, err)
	require.NoError(t, val.AddTruststore(store.Certificates()))

	// crls are empty
	val.crls.Range(func(key, value any) bool {
		crl := value.(*revocationList)
		assert.True(t, crl.lastUpdated.IsZero())
		return true
	})

	// Start triggers start
	val.start(ctx)
	val.sync() // blocks until sync is complete.

	// crls have been updated
	crl, ok := val.getCRL(rootCRLurl)
	require.True(t, ok)
	assert.False(t, crl.lastUpdated.IsZero())
	crl, ok = val.getCRL("http://crl.pkioverheid.nl/DomeinServerCA2020LatestCRL.crl")
	require.True(t, ok)
	assert.True(t, crl.lastUpdated.IsZero()) // pkiOverheid CA has expired, so is not updated
}

func TestValidator_Validate(t *testing.T) {
	val := newValidatorStarted(t)

	// load test certificates
	validCertA := loadCert(t, testdatapath+"/A-valid.pem")
	revokedCertA := loadCert(t, testdatapath+"/A-revoked.pem")
	validCertBWithRevokedCA := loadCert(t, testdatapath+"/B-valid_revoked-CA.pem")
	validCertC := loadCert(t, testdatapath+"/C-valid.pem")

	block, _ := pem.Decode([]byte(bannedTestCertificate))
	bannedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// testSoftHard runs the same test for both the soft-fail and hard-fail scenario
	testSoftHard := func(t *testing.T, val *validator, cert *x509.Certificate, softfailReturn error, hardfailReturn error) {
		fn := func(softbool bool, expected error) {
			val.softfail = softbool
			err = val.CheckCRL([]*x509.Certificate{cert})
			if expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, expected)
			}
		}
		fnStrict := func(expected error) {
			val.softfail = true // make sure it ignores the configured value
			err = val.CheckCRLStrict([]*x509.Certificate{cert})
			if expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, expected)
			}
		}
		t.Run("softfail", func(t *testing.T) {
			fn(true, softfailReturn)
		})
		t.Run("hardfail", func(t *testing.T) {
			fn(false, hardfailReturn)
			fnStrict(hardfailReturn)
		})
	}

	t.Run("ok", func(t *testing.T) {
		testSoftHard(t, val, validCertA, nil, nil)
	})
	t.Run("revoked cert", func(t *testing.T) {
		testSoftHard(t, val, revokedCertA, ErrCertRevoked, ErrCertRevoked)
	})
	t.Run("unknown issuer", func(t *testing.T) {
		val := &validator{}
		testSoftHard(t, val, validCertA, ErrCertUntrusted, ErrCertUntrusted)
	})
	t.Run("missing crl", func(t *testing.T) {
		testSoftHard(t, val, validCertBWithRevokedCA, nil, ErrCRLMissing)
	})
	t.Run("expired crl", func(t *testing.T) {
		testSoftHard(t, val, validCertC, nil, ErrCRLExpired)
	})
	t.Run("blocked cert", func(t *testing.T) {
		ts := denylistTestServer(trustedDenylist(t))
		defer ts.Close()
		val.denylist, err = testDenylist(ts.URL, publicKeyDoNotUse)
		require.NoError(t, err)

		testSoftHard(t, val, bannedCert, ErrCertBanned, ErrCertBanned)
	})
	t.Run("denylist missing", func(t *testing.T) {
		ts := denylistTestServer("")
		defer ts.Close()
		val.denylist, err = testDenylist(ts.URL, publicKeyDoNotUse)
		require.NoError(t, err)

		testSoftHard(t, val, bannedCert, nil, ErrDenylistMissing)
	})
}

func TestValidator_SetValidatePeerCertificateFunc(t *testing.T) {
	// certificates and tls config
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	leafCertFile := testdatapath + "/A-valid.pem"
	tlsCert, err := tls.LoadX509KeyPair(leafCertFile, leafCertFile)
	require.NoError(t, err)
	cfg := &tls.Config{
		RootCAs:      store.CertPool,
		Certificates: []tls.Certificate{tlsCert},
	}
	require.Nil(t, cfg.VerifyPeerCertificate)

	v := testValidator(t)
	require.NoError(t, v.AddTruststore(store.Certificates()))

	err = v.SetVerifyPeerCertificateFunc(cfg)

	require.NoError(t, err)
	assert.NotNil(t, cfg.VerifyPeerCertificate)

	t.Run("validates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		v.start(ctx)
		t.Run("ok", func(t *testing.T) {
			err := cfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{store.IntermediateCAs[0], store.RootCAs[0]}})
			assert.NoError(t, err)
		})
		t.Run("revoked cert", func(t *testing.T) {
			err := cfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{store.IntermediateCAs[1], store.RootCAs[0]}})
			assert.ErrorIs(t, err, ErrCertRevoked)
			expectedErr := new(tls.CertificateVerificationError)
			assert.ErrorAs(t, err, &expectedErr)
		})
	})
}

func TestValidator_AddTruststore(t *testing.T) {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		val, err := newValidator(TestConfig(t))
		require.NoError(t, err)

		err = val.AddTruststore(store.Certificates())

		assert.NotNil(t, val)
	})

	t.Run("missing CA", func(t *testing.T) {
		noRootStore := store.Certificates()[:2]
		val, err := newValidator(Config{Softfail: true})
		require.NoError(t, err)

		err = val.AddTruststore(noRootStore)

		assert.ErrorContains(t, err, "certificate's issuer is not in the trust store")
	})
}

func TestValidator_SubscribeDenied(t *testing.T) {
	mockDenylist := NewMockDenylist(gomock.NewController(t))
	mockDenylist.EXPECT().Subscribe(gomock.Any())

	val, err := newValidator(TestConfig(t))
	require.NoError(t, err)
	val.denylist = mockDenylist

	val.SubscribeDenied(func() { _ = "functions handles cannot be tested for equality" })
}

func Test_NewValidator(t *testing.T) {
	cfg := DefaultConfig()

	val, err := newValidator(cfg)

	require.NoError(t, err)
	assert.Equal(t, cfg.Softfail, val.softfail) // softfail is true, so fails if not set
	assert.Equal(t, cfg.MaxUpdateFailHours, val.maxUpdateFailHours)
	assert.Equal(t, cfg.Denylist.URL, val.denylist.URL())
}

func Test_ValidatorGetCRL(t *testing.T) {
	val := newValidatorStarted(t)

	t.Run("exists", func(t *testing.T) {
		result, ok := val.getCRL(rootCRLurl)

		assert.True(t, ok)
		assert.NotNil(t, result)
	})
	t.Run("does not exists", func(t *testing.T) {
		result, ok := val.getCRL("nope")

		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func Test_ValidatorAddEndpoint(t *testing.T) {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	intermediate, root := store.Certificates()[0], store.Certificates()[2]
	endpoint := []string{intermediate.CRLDistributionPoints[0]}

	t.Run("ok - only add once", func(t *testing.T) {
		val := &validator{}
		// only add once
		for i := 0; i < 3; i++ {
			err = val.addEndpoints(root, endpoint)
			require.NoError(t, err)
			counter := 0
			val.crls.Range(func(key, value any) bool {
				counter++
				return true
			})
			// stays one
			assert.Equal(t, 1, counter)
		}
	})
	t.Run("multiple issuers", func(t *testing.T) {
		val := &validator{}
		// first issuer for endpoint is valid
		err = val.addEndpoints(root, endpoint)
		require.NoError(t, err)
		// second issuer for endpoint returns error
		err = val.addEndpoints(intermediate, endpoint)
		assert.Error(t, err)
	})
}

func Test_ValidatorDownloadCRL(t *testing.T) {
	v := newValidatorStarted(t)
	t.Run("ok", func(t *testing.T) {
		rl, err := v.downloadCRL(rootCRLurl)

		assert.NoError(t, err)
		assert.Contains(t, rl.Issuer.String(), "Nuts Foundation")

	})
	t.Run("invalid URL", func(t *testing.T) {
		rl, err := v.downloadCRL("http://nuts.nl/error")

		assert.Error(t, err)
		assert.Nil(t, rl)
	})
	t.Run("invalid CRL", func(t *testing.T) {
		rl, err := v.downloadCRL("http://nuts.nl/invalid")

		assert.ErrorContains(t, err, "parse downloaded CRL: x509: malformed crl")
		assert.Nil(t, rl)
	})
}

func Test_ValidatorVerifyCRL(t *testing.T) {
	v := newValidatorStarted(t)
	trustStore, _ := core.LoadTrustStore(truststore)
	issuer := trustStore.Certificates()[3] // rootCA

	t.Run("ok", func(t *testing.T) {
		data, err := os.ReadFile(testdatapath + "/RootCALatest.crl")
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(data)
		require.NoError(t, err)

		err = v.verifyCRL(rl, issuer)

		assert.NoError(t, err)
	})

	t.Run("ca not in truststore", func(t *testing.T) {
		data, err := os.ReadFile(pkiOverheidCRL)
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(data)
		require.NoError(t, err)

		err = v.verifyCRL(rl, issuer)

		assert.EqualError(t, err, "crl signed by unexpected issuer: expected=CN=Root CA,O=Nuts Foundation,C=NL, got=CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL")
	})

	t.Run("invalid signature", func(t *testing.T) {
		// Create a CRL with an invalid signature (valid issuer cert, but signed with random private key)
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		crlWithInvalidSig, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1024)}, issuer, privateKey)
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(crlWithInvalidSig)
		require.NoError(t, err)

		err = v.verifyCRL(rl, issuer)

		assert.EqualError(t, err, "crl signature could not be verified: crypto/rsa: verification error")
	})
}

func Test_ValidatorUpdateCRL(t *testing.T) {
	crlEndpoint := rootCRLurl
	t.Run("ok", func(t *testing.T) {
		v := testValidator(t)

		// get the empty rl
		rl, ok := v.getCRL(crlEndpoint)
		require.True(t, ok)
		assert.True(t, rl.lastUpdated.IsZero())

		// update rl is successful
		err := v.updateCRL(crlEndpoint, rl)
		require.NoError(t, err)
		rl2, ok := v.getCRL(crlEndpoint)
		require.True(t, ok)
		assert.NotSame(t, rl, rl2)
	})
	t.Run("invalid CRL issuer", func(t *testing.T) {
		store, err := core.LoadTrustStore(truststore)
		require.NoError(t, err)
		v := testValidator(t)
		rl := newRevocationList(store.Certificates()[0])

		err = v.updateCRL(rootCRLurl, rl)

		assert.ErrorContains(t, err, "crl signed by unexpected issuer")
	})
}

func testValidator(t *testing.T) *validator {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	require.Len(t, store.Certificates(), 4)
	val, err := newValidatorWithHTTPClient(DefaultConfig(), newClient())
	require.NoError(t, err)
	require.NoError(t, val.AddTruststore(store.Certificates()))
	return val
}

// newValidatorStarted return a Started validator containing truststore
func newValidatorStarted(t *testing.T) *validator {
	val := testValidator(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	val.start(ctx)
	val.sync() // block until initial sync is completed
	return val
}

func newClient() *http.Client {
	return &http.Client{Transport: &fakeTransport{responseData: map[string][]byte{
		"/invalid": []byte("Definitely not a CRL"),
	}}}
}

type fakeTransport struct {
	mux          sync.Mutex
	responseData map[string][]byte
}

func (transport *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.mux.Lock()
	defer transport.mux.Unlock()
	// check for known data first
	data, ok := transport.responseData[req.URL.Path]
	if ok {
		return &http.Response{Body: readCloser{data: bytes.NewReader(data)}}, nil
	}

	// load data if not available
	if req.URL.Path == "/error" {
		return nil, errors.New("random error")
	}
	file, ok := crlPathMap[req.URL.Path]
	if !ok {
		panic("unknown CRL: " + file)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		//
		return nil, errors.New(file)
	}
	transport.responseData[file] = data
	return &http.Response{Body: readCloser{data: bytes.NewReader(transport.responseData[file])}}, nil
}

type readCloser struct {
	data *bytes.Reader
}

func (s readCloser) Read(p []byte) (n int, err error) {
	return s.data.Read(p)
}

func (s readCloser) Close() error {
	return nil
}

func loadCert(t *testing.T, file string) *x509.Certificate {
	data, _ := os.ReadFile(file)
	certs, err := core.ParseCertificates(data)
	require.NoError(t, err)
	require.Len(t, certs, 1)

	return certs[0]
}
