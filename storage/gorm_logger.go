package storage

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"time"
)

var _ logger.Interface = (*gormLogrusLogger)(nil)
var nowFunc = time.Now

// gormLogrusLogger is a logger that uses logrus as underlying logger for gorm
type gormLogrusLogger struct {
	underlying    *logrus.Entry
	slowThreshold time.Duration
}

func (g gormLogrusLogger) LogMode(level logger.LogLevel) logger.Interface {
	// Ignored, level determined by underlying logger
	return g
}

func (g gormLogrusLogger) Info(_ context.Context, msg string, args ...interface{}) {
	g.underlying.Infof(msg, args...)
}

func (g gormLogrusLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	g.underlying.Warnf(msg, args...)
}

func (g gormLogrusLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	g.underlying.Errorf(msg, args...)
}

func (g gormLogrusLogger) Trace(_ context.Context, begin time.Time, fn func() (sql string, rowsAffected int64), err error) {
	// If time since begin is greater than slowThreshold, log as warning
	// Otherwise, log on DEBUG
	elapsed := nowFunc().Sub(begin)
	sql, _ := fn()
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		g.underlying.WithError(err).Warnf("Query failed (took %s): %s", elapsed, sql)
		return
	}
	if elapsed >= g.slowThreshold {
		g.underlying.Warnf("Slow query (took %s): %s", elapsed, sql)
	} else {
		g.underlying.Debugf("Query (took %s): %s", elapsed, sql)
	}
}
