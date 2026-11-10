/*
 * Copyright (C) 2026 Nuts community
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/http/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicWebCA is a CA that is trusted as system root (not through the Nuts truststore), which serves its own CRL.
type publicWebCA struct {
	cert      *x509.Certificate
	key       *ecdsa.PrivateKey
	parent    *publicWebCA // nil for a root CA
	crlServer *httptest.Server
	// crl is the DER encoded CRL served by crlServer. If nil, the server responds with an error.
	crl atomic.Pointer[[]byte]
	// delay is how long crlServer waits before it responds.
	delay atomic.Int64
	// release makes waiting requests return without a response, so the server can be closed.
	release chan struct{}
}

func newPublicWebCA(t *testing.T) *publicWebCA {
	return newTestCA(t, nil)
}

// newIntermediateCA returns a CA issued by this CA, with this CA's CRL endpoint.
func (ca *publicWebCA) newIntermediateCA(t *testing.T) *publicWebCA {
	return newTestCA(t, ca)
}

func newTestCA(t *testing.T, parent *publicWebCA) *publicWebCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Public Web Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, issuerKey := template, key
	if parent != nil {
		template.Subject.CommonName = "Public Web Test Intermediate CA"
		template.CRLDistributionPoints = []string{parent.crlServer.URL + "/ca.crl"}
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	ca := &publicWebCA{cert: cert, key: key, parent: parent, release: make(chan struct{})}
	ca.crlServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		select {
		case <-time.After(time.Duration(ca.delay.Load())):
		case <-ca.release:
			return
		}
		crl := ca.crl.Load()
		if crl == nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write(*crl)
	}))
	t.Cleanup(ca.crlServer.Close)
	// Cleanup runs in reverse order: release waiting requests first, otherwise crlServer.Close blocks on them.
	t.Cleanup(func() { close(ca.release) })
	return ca
}

// publishCRL makes the CA serve a CRL that lists the given serial numbers as revoked.
func (ca *publicWebCA) publishCRL(t *testing.T, revoked ...*big.Int) {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serialNumber := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serialNumber, RevocationTime: time.Now()})
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	require.NoError(t, err)
	ca.crl.Store(&crl)
}

// startServer starts a HTTPS server with a certificate with the given serial number, issued by the CA.
func (ca *publicWebCA) startServer(t *testing.T, serialNumber *big.Int) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "public-web.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		CRLDistributionPoints: []string{ca.crlServer.URL + "/ca.crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	chain := [][]byte{der}
	if ca.parent != nil {
		chain = append(chain, ca.cert.Raw)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}}
	// Some tests fail the handshake on purpose, keep that out of the test output.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// TestPKI_PublicWebTLS tests the CRL check on outbound HTTPS through the production HTTP clients,
// for a chain that is trusted as system root and is unknown to the Nuts truststore.
func TestPKI_PublicWebTLS(t *testing.T) {
	serialNumber := big.NewInt(1234)

	// setup configures the PKI engine and makes the CA a trusted root.
	setup := func(t *testing.T, ca *publicWebCA, softfail bool) *PKI {
		t.Helper()
		tlsConfig := client.SafeHttpTransport.TLSClientConfig
		oldRootCAs, oldVerify := tlsConfig.RootCAs, tlsConfig.VerifyPeerCertificate
		t.Cleanup(func() {
			client.SafeHttpTransport.CloseIdleConnections()
			tlsConfig.RootCAs, tlsConfig.VerifyPeerCertificate = oldRootCAs, oldVerify
		})
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AddCert(ca.cert)

		engine := New()
		engine.config = TestConfig(t)
		engine.config.Softfail = softfail
		require.NoError(t, engine.Configure(core.ServerConfig{}))
		return engine
	}
	get := func(t *testing.T, httpClient *client.StrictHTTPClient, server *httptest.Server) error {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		response, err := httpClient.Do(request)
		if err != nil {
			return err
		}
		assert.Equal(t, http.StatusOK, response.StatusCode)
		return nil
	}

	t.Run("certificate not on the CRL is accepted", func(t *testing.T) {
		ca := newPublicWebCA(t)
		ca.publishCRL(t)
		setup(t, ca, false)

		err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

		assert.NoError(t, err)
	})
	t.Run("revoked certificate is rejected, also with softfail", func(t *testing.T) {
		ca := newPublicWebCA(t)
		ca.publishCRL(t, serialNumber)
		setup(t, ca, true)

		err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

		assert.ErrorIs(t, err, ErrCertRevoked)
		verificationErr := new(tls.CertificateVerificationError)
		assert.ErrorAs(t, err, &verificationErr)
	})
	t.Run("denylisted CA is rejected, also with softfail", func(t *testing.T) {
		ca := newPublicWebCA(t)
		ca.publishCRL(t)
		engine := setup(t, ca, true)
		SetNewDenylistWithCert(t, engine, ca.cert)

		err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

		assert.ErrorIs(t, err, ErrCertBanned)
	})
	t.Run("CRL can't be downloaded", func(t *testing.T) {
		t.Run("softfail accepts the certificate", func(t *testing.T) {
			ca := newPublicWebCA(t)
			setup(t, ca, true)

			err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

			assert.NoError(t, err)
		})
		t.Run("hardfail rejects the certificate", func(t *testing.T) {
			ca := newPublicWebCA(t)
			setup(t, ca, false)

			err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

			assert.ErrorIs(t, err, ErrCRLMissing)
		})
	})
	t.Run("applies to the client with response caching", func(t *testing.T) {
		ca := newPublicWebCA(t)
		ca.publishCRL(t, serialNumber)
		setup(t, ca, true)
		oldTransport := client.DefaultCachingTransport
		t.Cleanup(func() { client.DefaultCachingTransport = oldTransport })
		client.DefaultCachingTransport = client.NewCachingTransport(client.SafeHttpTransport, 1024)

		err := get(t, client.NewWithCache(5*time.Second), ca.startServer(t, serialNumber))

		assert.ErrorIs(t, err, ErrCertRevoked)
	})
	t.Run("waiting for a CRL download", func(t *testing.T) {
		const wait = 500 * time.Millisecond
		setCRLDownloadWait := func(t *testing.T) {
			old := crlDownloadWait
			crlDownloadWait = wait
			t.Cleanup(func() { crlDownloadWait = old })
		}

		t.Run("CRL endpoint hangs, softfail accepts the certificate without waiting for the client timeout", func(t *testing.T) {
			setCRLDownloadWait(t)
			ca := newPublicWebCA(t)
			ca.publishCRL(t)
			ca.delay.Store(int64(time.Hour))
			setup(t, ca, true)

			start := time.Now()
			err := get(t, client.New(5*time.Second), ca.startServer(t, serialNumber))

			assert.NoError(t, err)
			assert.Less(t, time.Since(start), 2*time.Second)
		})
		t.Run("2 CRL endpoints hang, the wait is shared, so softfail still applies within the client timeout", func(t *testing.T) {
			setCRLDownloadWait(t)
			root := newPublicWebCA(t)
			root.publishCRL(t)
			root.delay.Store(int64(time.Hour))
			intermediate := root.newIntermediateCA(t)
			intermediate.publishCRL(t)
			intermediate.delay.Store(int64(time.Hour))
			setup(t, root, true)

			// A wait per CRL (2 * wait) would exceed the client timeout.
			err := get(t, client.New(wait+300*time.Millisecond), intermediate.startServer(t, serialNumber))

			assert.NoError(t, err)
		})
		t.Run("2 slow CRL endpoints download concurrently, so both are checked in time", func(t *testing.T) {
			setCRLDownloadWait(t)
			delay := wait * 6 / 10 // one after another (2 * delay) would exceed the wait
			root := newPublicWebCA(t)
			root.publishCRL(t)
			root.delay.Store(int64(delay))
			intermediate := root.newIntermediateCA(t)
			intermediate.publishCRL(t)
			intermediate.delay.Store(int64(delay))
			setup(t, root, false) // hardfail: a CRL that isn't there in time rejects the certificate

			err := get(t, client.New(5*time.Second), intermediate.startServer(t, serialNumber))

			assert.NoError(t, err)
		})
		t.Run("slow CRL endpoint, download continues in the background", func(t *testing.T) {
			setCRLDownloadWait(t)
			ca := newPublicWebCA(t)
			ca.publishCRL(t, serialNumber)
			ca.delay.Store(int64(3 * wait))
			setup(t, ca, true)
			server := ca.startServer(t, serialNumber)
			httpClient := client.New(5 * time.Second)

			// The CRL isn't there in time, so softfail accepts the certificate.
			err := get(t, httpClient, server)
			require.NoError(t, err)

			// Once the download finished, a new connection is checked against the CRL.
			assert.Eventually(t, func() bool {
				client.SafeHttpTransport.CloseIdleConnections()
				return errors.Is(get(t, httpClient, server), ErrCertRevoked)
			}, 5*time.Second, 100*time.Millisecond)
		})
	})
}
