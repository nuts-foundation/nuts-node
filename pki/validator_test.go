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
	"errors"
	"go.uber.org/goleak"
	"math/big"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

// testConfig provides a validator module configuration for tests
func pkiCfg() pkiconfig.Config {
	return pkiconfig.Config{
		MaxUpdateFailHours: 4,
	}
}

func TestValidator_Start(t *testing.T) {
	defer goleak.VerifyNone(t)
	store, err := core.LoadTrustStore(truststorePKIo)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	val, err := newValidatorWithHTTPClient(pkiCfg(), store.Certificates(), newClient())
	require.NoError(t, err)

	// crls are empty
	val.crls.Range(func(key, value any) bool {
		crl := value.(*revocationList)
		assert.True(t, crl.lastUpdated.IsZero())
		return true
	})

	// Start triggers start
	val.Start(ctx)
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
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		err := val.Validate([]*x509.Certificate{store.IntermediateCAs[0]})
		assert.NoError(t, err)
	})
	t.Run("revoked cert", func(t *testing.T) {
		err := val.Validate(store.IntermediateCAs)
		assert.ErrorIs(t, err, ErrCertRevoked)
	})
}

func TestValidator_SetValidatePeerCertificateFunc(t *testing.T) {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	newCfg := func(leafCertFile string) *tls.Config {
		tlsCert, err := tls.LoadX509KeyPair(leafCertFile, leafCertFile)
		require.NoError(t, err)
		return &tls.Config{
			RootCAs:      store.CertPool,
			Certificates: []tls.Certificate{tlsCert},
		}
	}
	t.Run("set - ok", func(t *testing.T) {
		cfg := newCfg(testdatapath + "/A-valid.pem")
		v := newValidator(t)
		require.Nil(t, cfg.VerifyPeerCertificate)

		err := v.SetValidatePeerCertificateFunc(cfg)

		require.NoError(t, err)
		assert.NotNil(t, cfg.VerifyPeerCertificate)
		crl, exists := v.getCRL("http://certs.nuts.nl/IntermediateCAALatest.crl")
		assert.True(t, exists)
		assert.NotNil(t, crl)

		t.Run("validates", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v.Start(ctx)
			v.sync()
			t.Run("ok", func(t *testing.T) {
				err := cfg.VerifyPeerCertificate([][]byte{store.IntermediateCAs[0].Raw, store.RootCAs[0].Raw}, nil)
				assert.NoError(t, err)
			})
			t.Run("revoked cert", func(t *testing.T) {
				err := cfg.VerifyPeerCertificate([][]byte{store.IntermediateCAs[1].Raw, store.RootCAs[0].Raw}, nil)
				assert.ErrorIs(t, err, ErrCertRevoked)
			})
			t.Run("invalid cert data", func(t *testing.T) {
				err := cfg.VerifyPeerCertificate([][]byte{[]byte("definitely not"), []byte("valid certs")}, nil)
				assert.Error(t, err)
			})
		})
	})

	t.Run("error - contains cert that is not in truststore", func(t *testing.T) {
		v := newValidator(t)

		err := v.SetValidatePeerCertificateFunc(newCfg("../test/pki/certificate-and-key.pem"))

		assert.EqualError(t, err, "tls.Config contains certificate from issuer that is not in the truststore: CN=localhost")
	})
}

func Test_New(t *testing.T) {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		val, err := NewValidator(pkiCfg(), store.Certificates())
		require.NoError(t, err)
		assert.NotNil(t, val)
	})

	t.Run("invalid truststore", func(t *testing.T) {
		noRootStore := store.Certificates()[:2]
		_, err = NewValidator(pkiCfg(), noRootStore)
		assert.ErrorContains(t, err, "certificate's issuer is not in the trust store")
	})
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

func Test_ValidatorValidateChain(t *testing.T) {
	val := newValidatorStarted(t)

	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		certs := []*x509.Certificate{store.Certificates()[0], store.Certificates()[2]} // slice without the revoked cert
		err = val.Validate(certs)
		assert.NoError(t, err)
	})
	t.Run("error - contains revoked cert", func(t *testing.T) {
		err = val.Validate(store.Certificates())
		assert.ErrorIs(t, err, ErrCertRevoked)
		assert.ErrorContains(t, err, "subject=CN=Intermediate B CA, S/N=3, issuer=CN=Root CA,O=Nuts Foundation,C=NL")
	})
}

func Test_ValidatorValidateCert(t *testing.T) {
	val := newValidatorStarted(t)
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		cert := loadCert(t, testdatapath+"/A-valid.pem")

		err := val.validateCert(cert)

		assert.NoError(t, err)
	})
	t.Run("revoked cert", func(t *testing.T) {
		cert := loadCert(t, testdatapath+"/A-revoked.pem")

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCertRevoked)
	})
	t.Run("unknown issuer", func(t *testing.T) {
		val := &validator{
			truststore: map[string]*x509.Certificate{},
		}
		cert := loadCert(t, testdatapath+"/A-valid.pem")

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCertUntrusted)
	})
	t.Run("missing crl", func(t *testing.T) {
		val := newValidatorStarted(t)
		cert := loadCert(t, testdatapath+"/B-valid_revoked-CA.pem")

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCRLMissing)
	})
	t.Run("expired crl", func(t *testing.T) {
		cert := store.IntermediateCAs[0]
		crl, ok := val.getCRL(cert.CRLDistributionPoints[0])
		require.True(t, ok)
		crl.list.NextUpdate = time.Time{}
		val.crls.Store(cert.CRLDistributionPoints[0], crl)

		err := val.validateCert(store.IntermediateCAs[0])

		assert.ErrorIs(t, err, ErrCRLExpired)
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
	issuer := trustStore.Certificates()[2] // rootCA

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
	t.Run("ok - update flows", func(t *testing.T) {
		v := newValidator(t)

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

		// do not update if the crl.SerialNumber has not changed
		err = v.updateCRL(crlEndpoint, rl2)
		require.NoError(t, err)
		rl3, ok := v.getCRL(crlEndpoint)
		require.True(t, ok)
		assert.Same(t, rl3, rl2)

		// update if the crl.SerialNumber has increased
		lowerCRLNumber := big.NewInt(0)
		rl2.list.Number = lowerCRLNumber
		err = v.updateCRL(crlEndpoint, rl2)
		require.NoError(t, err)
		rl4, ok := v.getCRL(crlEndpoint)
		require.True(t, ok)
		assert.NotSame(t, rl4, rl2)
	})
	t.Run("invalid CRL issuer", func(t *testing.T) {
		store, err := core.LoadTrustStore(truststore)
		require.NoError(t, err)
		v := newValidator(t)
		rl := newRevocationList(store.Certificates()[0])

		err = v.updateCRL(rootCRLurl, rl)

		assert.ErrorContains(t, err, "crl signed by unexpected issuer")
	})
}

func newValidator(t *testing.T) *validator {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	require.Len(t, store.Certificates(), 3)
	val, err := newValidatorWithHTTPClient(pkiCfg(), store.Certificates(), newClient())
	require.NoError(t, err)
	return val
}

// newValidatorStarted return a Started validator containing truststore
func newValidatorStarted(t *testing.T) *validator {
	val := newValidator(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	val.Start(ctx)
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
