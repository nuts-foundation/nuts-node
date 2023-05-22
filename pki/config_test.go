package pki

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, 4, cfg.MaxUpdateFailHours)
	assert.True(t, cfg.Softfail)
	require.NotNil(t, cfg.Denylist)
	assert.Empty(t, cfg.Denylist.TrustedSigner)
	assert.Empty(t, cfg.Denylist.URL)
}
