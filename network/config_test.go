package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	defs := DefaultConfig()
	assert.True(t, defs.EnableTLS)
	assert.Equal(t, 2000, defs.AdvertHashesInterval)
	assert.Equal(t, ":5555", defs.GrpcAddr)
}

func TestConfig_loadTrustStore(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = "test/truststore.pem"
		store, err := cfg.loadTrustStore()
		assert.NoError(t, err)
		assert.NotNil(t, store)
	})
	t.Run("invalid PEM file", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = "config_test.go"
		store, err := cfg.loadTrustStore()
		assert.Error(t, err)
		assert.Nil(t, store)
	})
	t.Run("not configured", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = ""
		store, err := cfg.loadTrustStore()
		assert.Error(t, err)
		assert.Nil(t, store)
	})
}
