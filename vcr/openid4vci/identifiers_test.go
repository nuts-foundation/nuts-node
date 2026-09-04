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

package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selfSignedCertWithSAN generates a minimal self-signed certificate with a single DNS SAN, so tests
// relying on it don't also trigger resolution attempts against unrelated real hostnames.
func selfSignedCertWithSAN(t *testing.T, dnsName string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

var issuerDID = did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")
var issuerIdentifier = "http://example.com/n2n/identity/" + issuerDID.String()
var issuerService = did.Service{
	ServiceEndpoint: "http://example.com/",
}
var issuerQuery = ssi.MustParseURI(issuerDID.String() + "/serviceEndpoint?type=" + resolver.BaseURLServiceType)

func TestDIDIdentifierResolver_Resolve(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := resolver.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(issuerQuery, resolver.DefaultMaxServiceReferenceDepth).Return(issuerService, nil)
		resolver := DIDIdentifierResolver{ServiceResolver: serviceResolver}

		identifier, err := resolver.Resolve(issuerDID)

		require.NoError(t, err)
		require.Equal(t, issuerIdentifier, identifier)
	})
	t.Run("DID not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := resolver.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(issuerQuery, resolver.DefaultMaxServiceReferenceDepth).Return(did.Service{}, resolver.ErrNotFound)
		resolver := DIDIdentifierResolver{ServiceResolver: serviceResolver}

		identifier, err := resolver.Resolve(issuerDID)

		require.NoError(t, err)
		require.Empty(t, identifier)
	})
	t.Run("service not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := resolver.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(issuerQuery, resolver.DefaultMaxServiceReferenceDepth).Return(did.Service{}, resolver.ErrServiceNotFound)
		resolver := DIDIdentifierResolver{ServiceResolver: serviceResolver}

		identifier, err := resolver.Resolve(issuerDID)

		require.NoError(t, err)
		require.Empty(t, identifier)
	})
	t.Run("invalid service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := resolver.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(issuerQuery, resolver.DefaultMaxServiceReferenceDepth).
			Return(did.Service{ServiceEndpoint: map[string]string{"foo": "bar"}}, nil)
		resolver := DIDIdentifierResolver{ServiceResolver: serviceResolver}

		identifier, err := resolver.Resolve(issuerDID)

		require.NoError(t, err)
		require.Empty(t, identifier)
	})
	t.Run("other error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := resolver.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(issuerQuery, resolver.DefaultMaxServiceReferenceDepth).Return(did.Service{}, errors.New("b00m!"))
		resolver := DIDIdentifierResolver{ServiceResolver: serviceResolver}

		identifier, err := resolver.Resolve(issuerDID)

		require.EqualError(t, err, "unable to resolve node-http-services-baseurl service: b00m!")
		require.Empty(t, identifier)
	})
}

func TestTLSIdentifierResolver(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{pki.Certificate()},
		InsecureSkipVerify: true,
	}
	id := did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

	t.Run("ok - resolved from certificate SAN", func(t *testing.T) {
		httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/.well-known/openid-credential-issuer") {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		httpServer.TLS = tlsConfig.Clone()
		httpServer.StartTLS()
		t.Cleanup(httpServer.Close)

		// TLSIdentifierResolver normally resolves to 443, but the port is dictated by httpstest, so determine port and overwrite the default.
		serverURL, _ := url.Parse(httpServer.URL)
		tlsIdentifierResolverPort, _ = strconv.Atoi(serverURL.Port())
		serverURL.Host = "localhost:" + strconv.Itoa(tlsIdentifierResolverPort) // httptest sets it to 127.0.0.1, but then the identifier won't match the certificate SAN.
		expected := serverURL.String() + "/n2n/identity/" + id.String()

		ctrl := gomock.NewController(t)
		underlying := NewMockIdentifierResolver(ctrl)
		underlying.EXPECT().Resolve(gomock.Any()).MinTimes(1).Return("", nil)

		resolver := NewTLSIdentifierResolver(underlying, httpServer.TLS)
		actual, err := resolver.Resolve(id)

		require.NoError(t, err)
		require.Equal(t, expected, actual)

		t.Run("identifier is cached for second invocation", func(t *testing.T) {
			httpServer.Close()

			actual, err := resolver.Resolve(id)

			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	})
	t.Run("unable to resolve from certificate SAN", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := NewMockIdentifierResolver(ctrl)
		underlying.EXPECT().Resolve(gomock.Any()).Return("", nil)

		actual, err := NewTLSIdentifierResolver(underlying, tlsConfig).Resolve(id)

		require.NoError(t, err)
		require.Equal(t, "", actual)
	})
	t.Run("empty result is cached briefly, not forever", func(t *testing.T) {
		// A local server that always says "not found", using a single-SAN certificate so resolution
		// only ever tries this local server (no real network dial timeouts against unrelated hosts) -
		// this test is about caching behavior, not network latency.
		localCert := selfSignedCertWithSAN(t, "localhost")
		localTLSConfig := &tls.Config{Certificates: []tls.Certificate{localCert}, InsecureSkipVerify: true}
		httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		httpServer.TLS = localTLSConfig.Clone()
		httpServer.StartTLS()
		t.Cleanup(httpServer.Close)
		serverURL, _ := url.Parse(httpServer.URL)
		tlsIdentifierResolverPort, _ = strconv.Atoi(serverURL.Port())

		originalInterval := tlsAttemptInterval
		tlsAttemptInterval = 50 * time.Millisecond
		t.Cleanup(func() { tlsAttemptInterval = originalInterval })

		ctrl := gomock.NewController(t)
		underlying := NewMockIdentifierResolver(ctrl)
		// Called twice: once for the initial (empty) resolution, and once more after the next
		// TLS-attempt is due, proving a later fix (e.g. a missing service being added) is picked up
		// without requiring a restart.
		underlying.EXPECT().Resolve(gomock.Any()).Times(2).Return("", nil)

		resolver := NewTLSIdentifierResolver(underlying, httpServer.TLS)

		actual, err := resolver.Resolve(id)
		require.NoError(t, err)
		require.Equal(t, "", actual)

		// Immediately calling again must be a cache hit (no additional underlying.Resolve call yet).
		actual, err = resolver.Resolve(id)
		require.NoError(t, err)
		require.Equal(t, "", actual)

		time.Sleep(100 * time.Millisecond)

		actual, err = resolver.Resolve(id)
		require.NoError(t, err)
		require.Equal(t, "", actual)
	})
	t.Run("ok - resolved from underlying resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := NewMockIdentifierResolver(ctrl)
		underlying.EXPECT().Resolve(gomock.Any()).Return("http://example.com", nil)

		actual, err := NewTLSIdentifierResolver(underlying, nil).Resolve(id)

		require.NoError(t, err)
		require.Equal(t, "http://example.com", actual)
	})
}
