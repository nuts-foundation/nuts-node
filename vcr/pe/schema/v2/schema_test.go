package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSchemaLoading(t *testing.T) {
	assert.NotNil(t, PresentationDefinition)
}

func TestValidate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		err := Validate([]byte(`{"id":"1", "input_descriptors": []}`), PresentationDefinition)
		assert.NoError(t, err)
	})
	t.Run("invalid", func(t *testing.T) {
		err := Validate([]byte(`{}`), PresentationDefinition)
		assert.ErrorContains(t, err, "doesn't validate")
		assert.ErrorContains(t, err, "missing properties: \"id\"")
	})
}
