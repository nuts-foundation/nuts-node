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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfig_tlsEnabled(t *testing.T) {
	assert.False(t, Config{}.tlsEnabled())
	assert.True(t, Config{trustStore: x509.NewCertPool()}.tlsEnabled())
}

func TestNewConfig(t *testing.T) {

	t.Run("without TLS", func(t *testing.T) {
		cfg := NewConfig(":1234", "foo")
		assert.Equal(t, transport.PeerID("foo"), cfg.peerID)
		assert.Equal(t, ":1234", cfg.listenAddress)
		assert.Nil(t, cfg.serverCert)
		assert.Nil(t, cfg.clientCert)
		assert.Nil(t, cfg.trustStore)
	})
	t.Run("with TLS", func(t *testing.T) {
		tlsCert, _ := tls.LoadX509KeyPair(testCertAndKeyFile, testCertAndKeyFile)
		ts := &core.TrustStore{
			CertPool: x509.NewCertPool(),
		}
		cfg := NewConfig(":1234", "foo", WithTLS(tlsCert, ts, 10))
		assert.Equal(t, &tlsCert, cfg.clientCert)
		assert.Equal(t, &tlsCert, cfg.serverCert)
		assert.Same(t, ts.CertPool, cfg.trustStore)
	})
}
