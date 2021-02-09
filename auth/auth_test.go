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
}

func testInstance(t *testing.T, cfg Config) *Auth {
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	return NewAuthInstance(cfg, vdr.NewTestVDRInstance(testDirectory), cryptoInstance)
}
