package jsonld

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewJSONLDInstance(t *testing.T) {
	instance := NewJSONLDInstance()
	t.Run("it creates a new JSONLD instance", func(t *testing.T) {
		assert.Implements(t, (*JSONLD)(nil), instance)
	})

	t.Run("it implements the Named interface", func(t *testing.T) {
		assert.Implements(t, (*core.Named)(nil), instance)
	})

	t.Run("it implements the Injectable interface", func(t *testing.T) {
		assert.Implements(t, (*core.Injectable)(nil), instance)
	})

	t.Run("it contains a ContextMananger", func(t *testing.T) {
		cm := instance.ContextManager()
		assert.Implements(t, (*ContextManager)(nil), cm)
	})

	t.Run("as an injectable", func(t *testing.T) {
		injectable := instance.(core.Injectable)
		t.Run("it knows its name", func(t *testing.T) {
			assert.Equal(t, "JDONLD", injectable.Name())
		})

		t.Run("it returns its config", func(t *testing.T) {
			config := injectable.Config()
			assert.IsType(t, &Config{}, config)
			jsonldConfig := config.(*Config)
			assert.Len(t, jsonldConfig.Contexts.LocalFileMapping, 4)
		})

		t.Run("as an configurable", func(t *testing.T) {
			configurable := instance.(core.Configurable)

			t.Run("it can be configured", func(t *testing.T) {
				configurable.Configure(core.ServerConfig{Strictmode: true})
				config := injectable.Config().(*Config)
				assert.True(t, config.strictMode)

			})
		})

	})
}
