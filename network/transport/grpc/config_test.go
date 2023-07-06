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
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/pki"
	testPKI "github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestConfig_tlsEnabled(t *testing.T) {
	assert.False(t, Config{}.tlsEnabled())
	assert.True(t, Config{trustStore: x509.NewCertPool()}.tlsEnabled())
}

func TestNewConfig(t *testing.T) {
	tlsCert := testPKI.Certificate()
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
	trustStore, _ := core.ParseTrustStore(testPKI.TruststoreData)
	clientCert := testPKI.Certificate()
	pkiMock := pki.NewMockValidator(gomock.NewController(t))
	pkiMock.EXPECT().SetVerifyPeerCertificateFunc(gomock.Any())

	tlsCfg, err := NewClientTLSConfig(&clientCert, trustStore.CertPool, pkiMock)

	require.NoError(t, err)
	assert.Same(t, trustStore.CertPool, tlsCfg.RootCAs)
	assert.Equal(t, clientCert, tlsCfg.Certificates[0])
	assert.Equal(t, core.MinTLSVersion, tlsCfg.MinVersion)
}
