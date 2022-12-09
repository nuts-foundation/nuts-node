package audit

import (
	"context"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLog(t *testing.T) {
	t.Run("it adds the audit fields to the logger", func(t *testing.T) {
		ctx := TestContext()

		actual := Log(ctx, logrus.NewEntry(logrus.StandardLogger()), "test")

		assert.Equal(t, "test", actual.Data["event"])
		assert.Equal(t, TestActor, actual.Data["actor"])
		assert.Equal(t, "audit", actual.Data["log"])
	})
	t.Run("it panics when no actor is set", func(t *testing.T) {
		assert.Panics(t, func() {
			Log(context.Background(), logrus.NewEntry(logrus.StandardLogger()), "test")
		})
	})
	t.Run("it panics when no event name is set", func(t *testing.T) {
		assert.Panics(t, func() {
			Log(TestContext(), logrus.NewEntry(logrus.StandardLogger()), "")
		})
	})
}
