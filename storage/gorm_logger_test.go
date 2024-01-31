package storage

import (
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

func Test_gormLogrusLogger_Trace(t *testing.T) {
	hook := &test.Hook{}
	underlying := logrus.New()
	underlying.SetLevel(logrus.TraceLevel)
	underlying.AddHook(hook)
	logger := gormLogrusLogger{
		underlying:    underlying.WithFields(nil),
		slowThreshold: 10 * time.Second,
	}
	now := time.Now()
	nowFunc = func() time.Time {
		return now
	}
	t.Run("execution error", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, assert.AnError)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query failed (took 1s): SELECT 1")
	})
	t.Run("normal query", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, nil)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query (took 1s): SELECT 1")
	})
	t.Run("record not found (error is ignored)", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, gorm.ErrRecordNotFound)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query (took 1s): SELECT 1")
	})
	t.Run("slow query", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-20*time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, nil)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Slow query (took 20s): SELECT 1")
	})
}
