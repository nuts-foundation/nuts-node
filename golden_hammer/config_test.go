package golden_hammer

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	assert.True(t, DefaultConfig().Enabled)
	assert.Greater(t, DefaultConfig().Interval, time.Minute)
	assert.Less(t, DefaultConfig().Interval, time.Hour)
}
