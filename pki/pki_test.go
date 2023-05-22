package pki

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_New(t *testing.T) {
	e := New()

	assert.IsType(t, &PKI{}, e)
	assert.Equal(t, DefaultConfig(), e.config)
	assert.Nil(t, e.validator)
}

func TestPKI_Name(t *testing.T) {
	e := New()
	assert.Equal(t, "PKI", e.Name())
}

func TestPKI_Config(t *testing.T) {
	e := New()

	cfgPtr := e.Config()

	assert.Same(t, &e.config, cfgPtr)
	assert.IsType(t, Config{}, e.config)
}

func TestPKI_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := New()

		err := e.Configure(core.ServerConfig{})

		assert.NoError(t, err)
		assert.NotNil(t, e.validator)
	})
	t.Run("invalid config", func(t *testing.T) {
		e := New()
		e.config.Denylist = DenylistConfig{
			URL:           "example.com",
			TrustedSigner: "definitely not valid",
		}

		err := e.Configure(core.ServerConfig{})

		assert.Error(t, err)
	})
}

func TestPKI_Runnable(t *testing.T) {
	e := New()
	e.validator = &validator{}

	assert.Nil(t, e.ctx)
	assert.Nil(t, e.shutdown)

	err := e.Start()
	defer e.shutdown() // prevent go routine leak in the validator

	assert.NoError(t, err)
	assert.NotNil(t, e.ctx)
	assert.NotNil(t, e.shutdown)

	err = e.Shutdown()

	assert.NoError(t, err)
	assert.ErrorIs(t, e.ctx.Err(), context.Canceled)
}
