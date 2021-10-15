package log

import (
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestLog(t *testing.T) {
	t.Run("can log", func(t *testing.T) {
		Logger().Info("Works")
	})
	t.Run("has correct module field", func(t *testing.T) {
		assert.Equal(t, Logger().Data["module"], "Auth")
	})
}
