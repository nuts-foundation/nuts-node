/*
 * Copyright (C) 2025 Nuts community
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

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureTrustBundle(t *testing.T) {
	// ConfigureTrustBundle mutates the global SafeHttpTransport, so reset it after each subtest.
	resetTransport := func(t *testing.T) {
		original := SafeHttpTransport.TLSClientConfig.RootCAs
		t.Cleanup(func() {
			SafeHttpTransport.TLSClientConfig.RootCAs = original
		})
		SafeHttpTransport.TLSClientConfig.RootCAs = nil
	}

	t.Run("empty directory argument is a no-op", func(t *testing.T) {
		resetTransport(t)

		err := ConfigureTrustBundle("")

		require.NoError(t, err)
		assert.Nil(t, SafeHttpTransport.TLSClientConfig.RootCAs)
	})
	t.Run("non-existent directory returns an error", func(t *testing.T) {
		resetTransport(t)

		err := ConfigureTrustBundle(filepath.Join(t.TempDir(), "does-not-exist"))

		require.Error(t, err)
		assert.Nil(t, SafeHttpTransport.TLSClientConfig.RootCAs)
	})
	t.Run("loads .pem and .crt files", func(t *testing.T) {
		resetTransport(t)
		dir := t.TempDir()
		caCert, caKey := newTestCA(t)
		writePEM(t, filepath.Join(dir, "ca.pem"), caCert.Raw)
		otherCA, _ := newTestCA(t)
		writePEM(t, filepath.Join(dir, "other.crt"), otherCA.Raw)
		// files with other extensions are ignored
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a certificate"), 0644))

		err := ConfigureTrustBundle(dir)

		require.NoError(t, err)
		pool := SafeHttpTransport.TLSClientConfig.RootCAs
		require.NotNil(t, pool)
		// A leaf signed by the loaded CA must verify against the configured pool, proving the CA was added.
		leaf := newTestLeaf(t, caCert, caKey)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
		assert.NoError(t, err)
	})
	t.Run("invalid certificate file returns an error", func(t *testing.T) {
		resetTransport(t)
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"), 0644))

		err := ConfigureTrustBundle(dir)

		assert.Error(t, err)
	})
}

// TestConfigureTrustBundle_endToEnd verifies that a client backed by SafeHttpTransport can only reach an HTTPS server
// whose certificate is signed by a custom CA after that CA is loaded via ConfigureTrustBundle.
func TestConfigureTrustBundle_endToEnd(t *testing.T) {
	original := SafeHttpTransport.TLSClientConfig.RootCAs
	t.Cleanup(func() { SafeHttpTransport.TLSClientConfig.RootCAs = original })
	SafeHttpTransport.TLSClientConfig.RootCAs = nil

	caCert, caKey := newTestCA(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{newTestServerCert(t, caCert, caKey)}}
	server.StartTLS()
	defer server.Close()

	// Before loading the CA, the server's certificate is signed by an unknown authority.
	_, err := New(time.Second).Do(mustGet(t, server.URL))
	require.Error(t, err)
	// Exact wording is platform-dependent (Go's verifier vs. the OS verifier), so match the common prefix.
	assert.Contains(t, err.Error(), "failed to verify certificate")

	// Load the CA into the trust bundle.
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.pem"), caCert.Raw)
	require.NoError(t, ConfigureTrustBundle(dir))

	// Now the server is trusted.
	response, err := New(time.Second).Do(mustGet(t, server.URL))
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, response.StatusCode)
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	return request
}

// newTestServerCert creates a TLS server certificate for 127.0.0.1, signed by the given CA.
func newTestServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTestCA creates a self-signed CA certificate for use in tests.
func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// newTestLeaf creates a leaf certificate signed by the given CA.
func newTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, data, 0644))
}
