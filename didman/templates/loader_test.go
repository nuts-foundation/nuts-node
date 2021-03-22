package templates

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadEmbeddedTemplates(t *testing.T) {
	tpl, err := LoadEmbeddedDefinitions()
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, tpl, 1)
}
