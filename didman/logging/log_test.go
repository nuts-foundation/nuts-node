package logging

import (
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestLog(t *testing.T) {
	t.Run("can log", func(t *testing.T) {
		Log().Info("Works")
	})
	t.Run("has correct module field", func(t *testing.T) {
		assert.Equal(t, Log().Data["module"], "DIDMan")
	})
}
