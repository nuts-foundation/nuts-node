package client

import (
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	v1 "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestNewCryptoClient_ServerMode(t *testing.T) {
	_, ok := NewCryptoClient().(*crypto.Crypto)
	assert.True(t, ok)
}

func TestNewCryptoClient_ClientMode(t *testing.T) {
	os.Setenv("NUTS_MODE", "cli")
	defer os.Unsetenv("NUTS_MODE")
	core.NutsConfig().Load(&cobra.Command{})
	_, ok := NewCryptoClient().(v1.HttpClient)
	assert.True(t, ok)
}
