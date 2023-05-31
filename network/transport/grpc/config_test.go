/*
 * Copyright (C) 2021 Nuts community
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

package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConfig_tlsEnabled(t *testing.T) {
	assert.False(t, Config{}.tlsEnabled())
	assert.True(t, Config{trustStore: x509.NewCertPool()}.tlsEnabled())
}

func TestNewConfig(t *testing.T) {
	tlsCert, _ := tls.LoadX509KeyPair(testCertAndKeyFile, testCertAndKeyFile)
	x509Cert, _ := x509.ParseCertificates(tlsCert.Certificate[0])
	ctrl := gomock.NewController(t)
	pkiMock := pki.NewMockValidator(ctrl)
	t.Run("without TLS", func(t *testing.T) {
		cfg, err := NewConfig(":1234", "foo")
		require.NoError(t, err)
		assert.Equal(t, transport.PeerID("foo"), cfg.peerID)
		assert.Equal(t, ":1234", cfg.listenAddress)
		assert.Nil(t, cfg.serverCert)
		assert.Nil(t, cfg.clientCert)
		assert.Nil(t, cfg.trustStore)
	})
	t.Run("with TLS", func(t *testing.T) {
		ts := &core.TrustStore{
			CertPool: x509.NewCertPool(),
		}
		pkiMock.EXPECT().AddTruststore(gomock.Any())
		cfg, err := NewConfig(":1234", "foo", WithTLS(tlsCert, ts, pkiMock))
		require.NoError(t, err)
		assert.Equal(t, &tlsCert, cfg.clientCert)
		assert.Equal(t, &tlsCert, cfg.serverCert)
		assert.Same(t, ts.CertPool, cfg.trustStore)
	})
	t.Run("error - invalid TLS config", func(t *testing.T) {
		ts := &core.TrustStore{
			CertPool: core.NewCertPool(x509Cert),
		}
		pkiMock.EXPECT().AddTruststore(gomock.Any())
		cfg, err := NewConfig(":1234", "foo", WithTLS(tlsCert, ts, pkiMock))
		require.NoError(t, err)
		assert.Equal(t, &tlsCert, cfg.clientCert)
		assert.Equal(t, &tlsCert, cfg.serverCert)
		assert.Same(t, ts.CertPool, cfg.trustStore)
	})
}

func Test_NewClientTLSConfig(t *testing.T) {
	trustStore, _ := core.LoadTrustStore(testTruststoreFile)
	clientCert, _ := tls.LoadX509KeyPair(testCertAndKeyFile, testCertAndKeyFile)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
	pkiMock := pki.NewMockValidator(gomock.NewController(t))
	pkiMock.EXPECT().SetVerifyPeerCertificateFunc(gomock.Any())

	tlsCfg, err := NewClientTLSConfig(&clientCert, trustStore.CertPool, pkiMock)

	require.NoError(t, err)
	assert.Same(t, trustStore.CertPool, tlsCfg.RootCAs)
	assert.Equal(t, clientCert, tlsCfg.Certificates[0])
	assert.Equal(t, core.MinTLSVersion, tlsCfg.MinVersion)
}
