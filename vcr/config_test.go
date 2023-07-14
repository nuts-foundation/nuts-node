package vcr

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	assert.True(t, DefaultConfig().OpenID4VCI.Enabled)
	assert.Equal(t, 5*time.Second, DefaultConfig().OpenID4VCI.Timeout)
}
