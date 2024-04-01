package assets

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTemplateLoading(t *testing.T) {
	// This test is here to make sure the templates are loaded correctly.
	// It doesn't test the actual content of the templates.
	assert.NotNil(t, ErrorTemplate)
}
