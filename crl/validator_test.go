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

package crl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

const (
	truststore     = "test/truststore.pem"
	truststorePKIo = "test/truststore_withPKIOverheid.pem"
	pkiOverheidCRL = "../network/test/pkioverheid.crl"
	rootCRLurl     = "http://certs.nuts.nl/RootCALatest.crl"
	//revokedSerialNumber = "10000026"
	//revokedIssuerName   = "CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL"
)

// crlPathMap maps the URI path to location on of CRL on disk
var crlPathMap = map[string]string{
	"/RootCALatest.crl":          "./test/RootCALatest.crl",
	"/IntermediateCAALatest.crl": "./test/IntermediateCAALatest.crl",
	"/IntermediateCABLatest.crl": "./test/IntermediateCABLatest.crl",
}

func TestValidator_Start(t *testing.T) {
	defer goleak.VerifyNone(t)
	store, err := core.LoadTrustStore(truststorePKIo)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, err)
	val := newValidatorWithHTTPClient(store.Certificates(), newClient())

	// crls are empty
	for _, rl := range val.crls {
		assert.True(t, rl.lastUpdated.IsZero())
	}

	validatorLoopStarted := make(chan struct{})
	go func(out chan struct{}) {
		val.crlChan <- func() {
			defer close(out)
			out <- struct{}{}
		}
	}(validatorLoopStarted)

	// Start triggers start
	time.Sleep(50 * time.Millisecond)
	assert.False(t, val.started)
	val.Start(ctx)
	<-validatorLoopStarted
	assert.True(t, val.started)

	// sleep to allow sync to complete
	time.Sleep(50 * time.Millisecond)

	// context cancel stops everything
	cancel()
	test.WaitFor(t, func() (bool, error) {
		return val.started == false, nil
	}, time.Second, "timeout waiting for crl validator to stop")
	// defer goleak.VerifyNone(t) at the top checks that routines are closed

	// crls have been updated
	assert.False(t, val.crls[rootCRLurl].lastUpdated.IsZero())                                                 // rootCRLurl is updated
	assert.True(t, val.crls["http://crl.pkioverheid.nl/DomeinServerCA2020LatestCRL.crl"].lastUpdated.IsZero()) // pkiOverheid CA has expired, so is not updated
}

func TestValidator_Validate(t *testing.T) {
	val := newValidatorStarted(t)
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		err := val.Validate(store.IntermediateCAs[0])
		assert.NoError(t, err)
	})
	t.Run("revoked cert", func(t *testing.T) {
		err := val.Validate(store.IntermediateCAs[1])
		assert.ErrorIs(t, err, ErrCertRevoked)
	})
	t.Run("validator not started", func(t *testing.T) {
		assert.EqualError(t, (&validator{}).Validate(nil), "CRL validator is not started")
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
		cfg := newCfg("./test/A-valid.pem")
		v := newValidator(t)
		require.Nil(t, cfg.VerifyPeerCertificate)

		err := v.SetValidatePeerCertificateFunc(cfg)

		require.NoError(t, err)
		assert.NotNil(t, cfg.VerifyPeerCertificate)
		assert.NotNil(t, v.crls["http://certs.nuts.nl/IntermediateCAALatest.crl"]) // intermediate CRL endpoint has been detected

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

	t.Run("error - must be called before Start", func(t *testing.T) {
		v := newValidatorStarted(t)

		err := v.SetValidatePeerCertificateFunc(newCfg("./test/A-valid.pem"))

		assert.EqualError(t, err, "SetVerifyPeerCertificateFunc must be called before Start")
	})

	t.Run("error - contains cert that is not in truststore", func(t *testing.T) {
		v := newValidator(t)

		err := v.SetValidatePeerCertificateFunc(newCfg("../network/test/certificate-and-key.pem"))

		assert.EqualError(t, err, "tls.Config contains certificate from issuer that is not in the truststore: CN=localhost")
	})
}

func Test_ValidatorGetCRLs(t *testing.T) {
	val := newValidatorStarted(t)

	result := val.getCRLs()

	assert.Len(t, result, 1)
	assert.NotNil(t, result[rootCRLurl])
	assert.Nil(t, result["does not exist"])
}

func Test_ValidatorGetCRL(t *testing.T) {
	val := newValidatorStarted(t)

	t.Run("exists", func(t *testing.T) {
		result, ok := val.getCRL(rootCRLurl)

		assert.True(t, ok)
		assert.NotNil(t, result)
	})
	t.Run("exists", func(t *testing.T) {
		result, ok := val.getCRL("nope")

		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func Test_ValidatorSetCRL(t *testing.T) {
	val := newValidatorStarted(t)

	expectedCRL := newRevocationList(&x509.Certificate{})
	val.setCRL("test", expectedCRL)

	require.NotNil(t, val.crls["test"])
	assert.Same(t, expectedCRL, val.crls["test"])
}

func Test_ValidatorValidateChain(t *testing.T) {
	val := newValidatorStarted(t)
	val.sync() // blocks until all crls are loaded

	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		certs := []*x509.Certificate{store.Certificates()[0], store.Certificates()[2]} // slice without the revoked cert
		err = val.validateChain(certs)
		assert.NoError(t, err)
	})
	t.Run("error - contains revoked cert", func(t *testing.T) {
		err = val.validateChain(store.Certificates())
		assert.ErrorIs(t, err, ErrCertRevoked)
		assert.ErrorContains(t, err, "subject=CN=Intermediate B CA, S/N=3, issuer=CN=Root CA,O=Nuts Foundation,C=NL")
	})
}

func Test_ValidatorValidateCert(t *testing.T) {
	val := newValidatorStarted(t)

	certA := loadCert(t, "./test/A-valid.pem")
	val.updateCRL(certA.CRLDistributionPoints[0], nil)
	certB := loadCert(t, "./test/B-valid_revoked-CA.pem")
	val.updateCRL(certB.CRLDistributionPoints[0], nil)

	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	val.sync() // blocks until all crls are loaded

	everythingExpired := time.Date(2030, 12, 1, 0, 0, 0, 0, time.UTC)

	t.Run("ok", func(t *testing.T) {
		cert := loadCert(t, "./test/A-valid.pem")

		err := val.validateCert(cert)

		assert.NoError(t, err)
	})
	t.Run("revoked cert", func(t *testing.T) {
		cert := loadCert(t, "./test/A-revoked.pem")

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCertRevoked)
	})
	t.Run("expired cert", func(t *testing.T) {
		cert := loadCert(t, "./test/A-expired.pem")
		nowFunc = func() time.Time { return everythingExpired }

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCertExpired)
	})
	t.Run("missing crl", func(t *testing.T) {
		val := newValidatorStarted(t)
		cert := loadCert(t, "./test/A-valid.pem")

		err := val.validateCert(cert)

		assert.ErrorIs(t, err, ErrCRLMissing)
	})
	t.Run("expired crl", func(t *testing.T) {
		nowFunc = func() time.Time { return everythingExpired }
		cert := store.IntermediateCAs[0]
		crl, ok := val.getCRL(cert.CRLDistributionPoints[0])
		require.True(t, ok)
		crl.list.NextUpdate = nowFunc()

		err := val.validateCert(store.IntermediateCAs[0])

		assert.ErrorIs(t, err, ErrCRLExpired)
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

	t.Run("ok", func(t *testing.T) {
		data, err := os.ReadFile("./test/RootCaLatest.crl")
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(data)
		require.NoError(t, err)

		err = v.verifyCRL(rl)

		assert.NoError(t, err)
	})

	t.Run("ca not in truststore", func(t *testing.T) {
		data, err := os.ReadFile(pkiOverheidCRL)
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(data)
		require.NoError(t, err)

		err = v.verifyCRL(rl)

		assert.EqualError(t, err, "signature could not be validated against known certificates")
	})

	t.Run("invalid signature", func(t *testing.T) {
		// Create a CRL with an invalid signature (valid issuer cert, but signed with random private key)
		trustStore, _ := core.LoadTrustStore(truststore)
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		issuer := trustStore.Certificates()[0]
		crlWithInvalidSig, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1024)}, issuer, privateKey)
		require.NoError(t, err)
		rl, err := x509.ParseRevocationList(crlWithInvalidSig)
		require.NoError(t, err)

		err = v.verifyCRL(rl)

		assert.EqualError(t, err, "crl signature could not be verified: crypto/rsa: verification error")
	})
}

func Test_ValidatorUpdateCRL(t *testing.T) {
	v := newValidator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.validatorLoop(ctx)
	crlEndpoint := rootCRLurl

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
}

func newValidator(t *testing.T) *validator {
	store, err := core.LoadTrustStore(truststore)
	require.NoError(t, err)
	require.Len(t, store.Certificates(), 3)
	val := newValidatorWithHTTPClient(store.Certificates(), newClient())
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
	responseData map[string][]byte
}

func (transport *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		panic(err)
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
	data, err := os.ReadFile(file)
	certs, err := core.ParseCertificates(data)
	require.NoError(t, err)
	require.Len(t, certs, 1)

	return certs[0]
}
