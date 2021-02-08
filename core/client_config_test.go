package core

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_GetAddress(t *testing.T) {
	t.Run("address has http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "https://localhost")
		defer os.Unsetenv("NUTS_ADDRESS")
		cfg := NewClientConfig()
		err := cfg.Load()
		assert.NoError(t, err)
		assert.Equal(t, "https://localhost", cfg.GetAddress())
	})
	t.Run("address has no http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "localhost")
		defer os.Unsetenv("NUTS_ADDRESS")
		cfg := NewClientConfig()
		err := cfg.Load()
		assert.NoError(t, err)
		assert.Equal(t, "http://localhost", cfg.GetAddress())
	})
}
