package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DefaultConfig(t *testing.T) {
	assert.Equal(t, Config{Port: 4022, Hostname: "localhost"}, DefaultConfig())
}
