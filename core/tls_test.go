package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadTrustStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		store, err := LoadTrustStore("../network/test/truststore.pem")
		assert.NoError(t, err)
		assert.NotNil(t, store)
	})
	t.Run("invalid PEM file", func(t *testing.T) {
		store, err := LoadTrustStore("tls_test.go")
		assert.Error(t, err)
		assert.Nil(t, store)
	})
}
