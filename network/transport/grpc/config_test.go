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
	assert.True(t, Config{TrustStore: x509.NewCertPool()}.tlsEnabled())
}

func TestNewConfig(t *testing.T) {
	t.Run("without TLS", func(t *testing.T) {
		cfg := NewConfig(":1234", "foo")
		assert.Equal(t, transport.PeerID("foo"), cfg.peerID)
		assert.Equal(t, ":1234", cfg.ListenAddress)
		assert.Nil(t, cfg.ServerCert.PrivateKey)
		assert.Nil(t, cfg.ClientCert.PrivateKey)
		assert.Nil(t, cfg.TrustStore)
	})
	t.Run("with TLS", func(t *testing.T) {
		cert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		ts := &core.TrustStore{
			CertPool: x509.NewCertPool(),
		}
		cfg := NewConfig(":1234", "foo", WithTLS(cert, ts, 10))
		assert.Equal(t, cert, cfg.ClientCert)
		assert.Equal(t, cert, cfg.ServerCert)
		assert.Same(t, ts.CertPool, cfg.TrustStore)
		assert.Equal(t, 10, cfg.MaxCRLValidityDays)
	})
}
