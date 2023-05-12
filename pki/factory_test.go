package pki

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateTLSConfig(t *testing.T) {
	cfg := core.NewServerConfig().TLS
	cfg.TrustStoreFile = "test/truststore.pem"
	cfg.CertFile = "test/A-valid.pem"
	cfg.CertKeyFile = "test/A-valid.pem"

	validator, tlsConfig, err := CreateTLSConfig(cfg)

	require.NoError(t, err)
	assert.NotNil(t, validator)
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
	assert.Equal(t, core.MinTLSVersion, tlsConfig.MinVersion)
	assert.NotEmpty(t, tlsConfig.Certificates)
	assert.NotNil(t, tlsConfig.RootCAs)
}
