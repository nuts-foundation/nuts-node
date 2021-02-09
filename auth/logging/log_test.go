package logging

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestLog(t *testing.T) {
	t.Run("can log", func(t *testing.T) {
		Log().Info("Works")
	})
	t.Run("has correct module field", func(t *testing.T) {
		assert.Equal(t, Log().Data["module"], "Auth")
	})
}
