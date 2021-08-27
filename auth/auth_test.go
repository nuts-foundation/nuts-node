package auth

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuth_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		i := NewTestAuthInstance(io.TestDirectory(t))
		_ = i.Configure(*core.NewServerConfig())
	})

	t.Run("ok - TLS files loaded", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.EnableTLS = true
		authCfg.TrustStoreFile = "test/certs/ca.pem"
		authCfg.CertKeyFile = "test/certs/example.com.key"
		authCfg.CertFile = "test/certs/example.com.pem"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, i.trustStore)
	})

	t.Run("error - no publicUrl", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "pbdf"
		i := testInstance(t, authCfg)
		cfg := core.NewServerConfig()
		cfg.Strictmode = true
		assert.Equal(t, ErrMissingPublicURL, i.Configure(*cfg))
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "non-existing"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - IRMA scheme manager not set", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = ""
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "IRMA SchemeManager must be set")
	})

	t.Run("error - only 'pbdf' IRMA scheme manager allow in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "demo"
		i := testInstance(t, authCfg)
		serverConfig := core.NewServerConfig()
		serverConfig.Strictmode = true
		err := i.Configure(*serverConfig)
		assert.EqualError(t, err, "in strictmode the only valid irma-scheme-manager is 'pbdf'")
	})

	t.Run("error - TLS required in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.PublicURL = "https://example.com"
		i := testInstance(t, authCfg)
		serverConfig := core.NewServerConfig()
		serverConfig.Strictmode = true
		err := i.Configure(*serverConfig)
		assert.EqualError(t, err, "in strictmode auth.enabletls must be true")
	})

	t.Run("error - unknown key/certificate when TLS enabled", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.EnableTLS = true
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "unable to load node TLS client certificate (certfile=,certkeyfile=): open : no such file or directory")
	})

	t.Run("error - unknown truststore when TLS enabled", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.EnableTLS = true
		authCfg.CertKeyFile = "test/certs/example.com.key"
		authCfg.CertFile = "test/certs/example.com.pem"
		authCfg.TrustStoreFile = "non-existing"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "unable to read trust store (file=non-existing): open non-existing: no such file or directory")
	})
}

func testInstance(t *testing.T, cfg Config) *Auth {
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	vcrInstance := vcr.NewTestVCRInstance(testDirectory)
	return NewAuthInstance(cfg, store.NewMemoryStore(), vcrInstance, cryptoInstance, nil)
}

func TestAuth_Name(t *testing.T) {
	assert.Equal(t, "Auth", (&Auth{}).Name())
}

func TestAuth_Config(t *testing.T) {
	assert.Equal(t, Config{}, *(&Auth{}).Config().(*Config))
}
