package pki

import (
	"github.com/stretchr/testify/require"
	"testing"

	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

func (p *PKI) SetConfig(t *testing.T, config pkiconfig.Config) {
	require.NotNil(t, t)
	p.config = config
}
