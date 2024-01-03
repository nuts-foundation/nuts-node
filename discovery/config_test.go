package discovery

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	assert.NotEmpty(t, DefaultConfig().Client.RegistrationRefreshInterval)
}
