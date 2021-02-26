package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	assert.Equal(t, DefaultConfig(), DefaultConfig())
	assert.NotSame(t, DefaultConfig(), DefaultConfig())
}