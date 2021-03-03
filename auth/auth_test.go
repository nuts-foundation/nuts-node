package auth

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuth_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		i := NewTestAuthInstance(io.TestDirectory(t))
		_ = i.Configure(*core.NewServerConfig())
	})

	t.Run("error - no publicUrl", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.PublicURL = ""
		authCfg.Irma.SchemeManager = "pbdf"
		i := testInstance(t, authCfg)
		cfg := core.NewServerConfig()
		cfg.Strictmode = true
		assert.Equal(t, ErrMissingPublicURL, i.Configure(*cfg))
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = "non-existing"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - IRMA scheme manager not set", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = ""
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "IRMA SchemeManager must be set")
	})

	t.Run("error - only 'pbdf' IRMA scheme manager allow in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = "demo"
		i := testInstance(t, authCfg)
		serverConfig := core.NewServerConfig()
		serverConfig.Strictmode = true
		err := i.Configure(*serverConfig)
		assert.EqualError(t, err, "in strictmode the only valid irma-scheme-manager is 'pbdf'")
	})
}

func testInstance(t *testing.T, cfg Config) *Auth {
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	return NewAuthInstance(cfg, vdr.NewTestVDRInstance(testDirectory), cryptoInstance)
}

func TestAuth_Name(t *testing.T) {
	assert.Equal(t, "Auth", (&Auth{}).Name())
}

func TestAuth_ConfigKey(t *testing.T) {
	assert.Equal(t, "auth", (&Auth{}).ConfigKey())
}

func TestAuth_Config(t *testing.T) {
	assert.Equal(t, Config{}, *(&Auth{}).Config().(*Config))
}
